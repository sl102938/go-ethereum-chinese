// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package keystore implements encrypted storage of secp256k1 private keys.
//
// Keys are stored as encrypted JSON files according to the Web3 Secret Storage specification.
// See https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition for more information.
package keystore

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
)

var (
	ErrLocked  = accounts.NewAuthNeededError("password or unlock")
	ErrNoMatch = errors.New("no key for given address or file")
	ErrDecrypt = errors.New("could not decrypt key with given password")

	// ErrAccountAlreadyExists is returned if an account attempted to import is already present in the keystore.
	// 如果尝试导入的帐户已存在于密钥库中，则返回 ErrAccountAlreadyExists。
	ErrAccountAlreadyExists = errors.New("account already exists")
)

// KeyStoreType is the reflect type of a keystore backend.
// KeyStoreType 是密钥库后端的反映类型。
var KeyStoreType = reflect.TypeOf(&KeyStore{})

// KeyStoreScheme is the protocol scheme prefixing account and wallet URLs.
// KeyStoreScheme 是前缀帐户和钱包 URL 的协议方案。
const KeyStoreScheme = "keystore"

// Maximum time between wallet refreshes (if filesystem notifications don't work).
// 钱包刷新之间的最长时间（如果文件系统通知不起作用）。
const walletRefreshCycle = 3 * time.Second

// KeyStore manages a key storage directory on disk.
// KeyStore 管理磁盘上的密钥存储目录。
type KeyStore struct {
	storage  keyStore                     // Storage backend, might be cleartext or encrypted // 存储后端，可能是明文或加密的
	cache    *accountCache                // In-memory account cache over the filesystem storage // 文件系统存储上的内存中帐户缓存
	changes  chan struct{}                // Channel receiving change notifications from the cache // 从缓存接收更改通知的通道
	unlocked map[common.Address]*unlocked // Currently unlocked account (decrypted private keys) // 当前已解锁的帐户（已解密的私钥）

	wallets     []accounts.Wallet       // Wallet wrappers around the individual key files // 各个密钥文件的钱包包装器
	updateFeed  event.Feed              // Event feed to notify wallet additions/removals // 用于通知钱包添加/删除的事件源
	updateScope event.SubscriptionScope // Subscription scope tracking current live listeners // 订阅范围跟踪当前的实时听众
	updating    bool                    // Whether the event notification loop is running // 事件通知循环是否正在运行

	mu       sync.RWMutex
	importMu sync.Mutex // Import Mutex locks the import to prevent two insertions from racing // Import Mutex 锁定导入以防止两次插入竞争
}

type unlocked struct {
	*Key
	abort chan struct{}
}

// NewKeyStore creates a keystore for the given directory.
// NewKeyStore 为给定目录创建密钥库。
func NewKeyStore(keydir string, scryptN, scryptP int) *KeyStore {
	keydir, _ = filepath.Abs(keydir)
	ks := &KeyStore{storage: &keyStorePassphrase{keydir, scryptN, scryptP, false}}
	ks.init(keydir)
	return ks
}

func (ks *KeyStore) init(keydir string) {
	// Lock the mutex since the account cache might call back with events
	// 锁定互斥锁，因为帐户缓存可能会回调事件
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Initialize the set of unlocked keys and the account cache
	// 初始化解锁密钥集和帐户缓存
	ks.unlocked = make(map[common.Address]*unlocked)
	ks.cache, ks.changes = newAccountCache(keydir)

	// TODO: In order for this finalizer to work, there must be no references to ks. addressCache doesn't keep a reference but unlocked keys do, so the finalizer will not trigger until all timed unlocks have expired.
	// TODO：为了使该终结器正常工作，必须没有对 ks 的引用。 addressCache 不保留引用，但解锁的键会保留，因此在所有定时解锁到期之前，终结器不会触发。
	runtime.SetFinalizer(ks, func(m *KeyStore) {
		m.cache.close()
	})
	// Create the initial list of wallets from the cache
	// 从缓存创建初始钱包列表
	accs := ks.cache.accounts()
	ks.wallets = make([]accounts.Wallet, len(accs))
	for i := 0; i < len(accs); i++ {
		ks.wallets[i] = &keystoreWallet{account: accs[i], keystore: ks}
	}
}

// Wallets implements accounts.Backend, returning all single-key wallets from the keystore directory.
// Wallets实现了accounts.Backend，从keystore目录返回所有单密钥钱包。
func (ks *KeyStore) Wallets() []accounts.Wallet {
	// Make sure the list of wallets is in sync with the account cache
	// 确保钱包列表与帐户缓存同步
	ks.refreshWallets()

	ks.mu.RLock()
	defer ks.mu.RUnlock()

	cpy := make([]accounts.Wallet, len(ks.wallets))
	copy(cpy, ks.wallets)
	return cpy
}

// refreshWallets retrieves the current account list and based on that does any necessary wallet refreshes.
// freshWallets 检索当前帐户列表，并根据该列表进行任何必要的钱包刷新。
func (ks *KeyStore) refreshWallets() {
	// Retrieve the current list of accounts
	// 检索当前帐户列表
	ks.mu.Lock()
	accs := ks.cache.accounts()

	// Transform the current list of wallets into the new one
	// 将当前钱包列表转换为新钱包列表
	var (
		wallets = make([]accounts.Wallet, 0, len(accs))
		events  []accounts.WalletEvent
	)

	for _, account := range accs {
		// Drop wallets while they were in front of the next account
		// 当钱包在下一个账户前时将其放下
		for len(ks.wallets) > 0 && ks.wallets[0].URL().Cmp(account.URL) < 0 {
			events = append(events, accounts.WalletEvent{Wallet: ks.wallets[0], Kind: accounts.WalletDropped})
			ks.wallets = ks.wallets[1:]
		}
		// If there are no more wallets or the account is before the next, wrap new wallet
		// 如果没有更多钱包或该帐户在下一个之前，请包装新钱包
		if len(ks.wallets) == 0 || ks.wallets[0].URL().Cmp(account.URL) > 0 {
			wallet := &keystoreWallet{account: account, keystore: ks}

			events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletArrived})
			wallets = append(wallets, wallet)
			continue
		}
		// If the account is the same as the first wallet, keep it
		// 如果账户与第一个钱包相同，则保留
		if ks.wallets[0].Accounts()[0] == account {
			wallets = append(wallets, ks.wallets[0])
			ks.wallets = ks.wallets[1:]
			continue
		}
	}
	// Drop any leftover wallets and set the new batch
	// 丢弃所有剩余的钱包并设置新的批次
	for _, wallet := range ks.wallets {
		events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletDropped})
	}
	ks.wallets = wallets
	ks.mu.Unlock()

	// Fire all wallet events and return
	// 触发所有钱包事件并返回
	for _, event := range events {
		ks.updateFeed.Send(event)
	}
}

// Subscribe implements accounts.Backend, creating an async subscription to receive notifications on the addition or removal of keystore wallets.
// Subscribe 实现accounts.Backend，创建异步订阅以接收有关添加或删除密钥库钱包的通知。
func (ks *KeyStore) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	// We need the mutex to reliably start/stop the update loop
	// 我们需要互斥锁来可靠地启动/停止更新循环
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Subscribe the caller and track the subscriber count
	// 订阅呼叫者并跟踪订阅者数量
	sub := ks.updateScope.Track(ks.updateFeed.Subscribe(sink))

	// Subscribers require an active notification loop, start it
	// 订阅者需要一个活动的通知循环，启动它
	if !ks.updating {
		ks.updating = true
		go ks.updater()
	}
	return sub
}

// updater is responsible for maintaining an up-to-date list of wallets stored in the keystore, and for firing wallet addition/removal events. It listens for account change events from the underlying account cache, and also periodically forces a manual refresh (only triggers for systems where the filesystem notifier is not running).
// 更新程序负责维护存储在密钥库中的最新钱包列表，并触发钱包添加/删除事件。它侦听来自底层帐户缓存的帐户更改事件，并定期强制手动刷新（仅在文件系统通知程序未运行的系统上触发）。
func (ks *KeyStore) updater() {
	for {
		// Wait for an account update or a refresh timeout
		// 等待帐户更新或刷新超时
		select {
		case <-ks.changes:
		case <-time.After(walletRefreshCycle):
		}
		// Run the wallet refresher
		// 运行钱包刷新
		ks.refreshWallets()

		// If all our subscribers left, stop the updater
		// 如果我们所有的订阅者都离开了，请停止更新程序
		ks.mu.Lock()
		if ks.updateScope.Count() == 0 {
			ks.updating = false
			ks.mu.Unlock()
			return
		}
		ks.mu.Unlock()
	}
}

// HasAddress reports whether a key with the given address is present.
// HasAddress 报告是否存在具有给定地址的密钥。
func (ks *KeyStore) HasAddress(addr common.Address) bool {
	return ks.cache.hasAddress(addr)
}

// Accounts returns all key files present in the directory.
// 帐户返回目录中存在的所有密钥文件。
func (ks *KeyStore) Accounts() []accounts.Account {
	return ks.cache.accounts()
}

// Delete deletes the key matched by account if the passphrase is correct. If the account contains no filename, the address must match a unique key.
// 如果密码正确，删除将删除与帐户匹配的密钥。如果帐户不包含文件名，则地址必须与唯一密钥匹配。
func (ks *KeyStore) Delete(a accounts.Account, passphrase string) error {
	// Decrypting the key isn't really necessary, but we do it anyway to check the password and zero out the key immediately afterwards.
	// 解密密钥并不是真正必要的，但我们无论如何都会这样做以检查密码并在之后立即将密钥清零。
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if key != nil {
		zeroKey(key.PrivateKey)
	}
	if err != nil {
		return err
	}
	// The order is crucial here. The key is dropped from the cache after the file is gone so that a reload happening in between won't insert it into the cache again.
	// 这里的顺序至关重要。文件消失后，密钥将从缓存中删除，因此中间发生的重新加载不会再次将其插入缓存中。
	err = os.Remove(a.URL.Path)
	if err == nil {
		ks.cache.delete(a)
		ks.refreshWallets()
	}
	return err
}

// SignHash calculates a ECDSA signature for the given hash. The produced signature is in the [R || S || V] format where V is 0 or 1.
// SignHash 计算给定哈希的 ECDSA 签名。生成的签名位于 [R || S || V] 格式，其中 V 为 0 或 1。
func (ks *KeyStore) SignHash(a accounts.Account, hash []byte) ([]byte, error) {
	// Look up the key to sign with and abort if it cannot be found
	// 查找要签名的密钥，如果找不到则中止
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	unlockedKey, found := ks.unlocked[a.Address]
	if !found {
		return nil, ErrLocked
	}
	// Sign the hash using plain ECDSA operations
	// 使用普通 ECDSA 操作对哈希进行签名
	return crypto.Sign(hash, unlockedKey.PrivateKey)
}

// SignTx signs the given transaction with the requested account.
// SignTx 使用请求的帐户签署给定的交易。
func (ks *KeyStore) SignTx(a accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	// Look up the key to sign with and abort if it cannot be found
	// 查找要签名的密钥，如果找不到则中止
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	unlockedKey, found := ks.unlocked[a.Address]
	if !found {
		return nil, ErrLocked
	}
	// Depending on the presence of the chain ID, sign with 2718 or homestead
	// 根据链 ID 的存在，使用 2718 或 homestead 进行签名
	signer := types.LatestSignerForChainID(chainID)
	return types.SignTx(tx, signer, unlockedKey.PrivateKey)
}

// SignHashWithPassphrase signs hash if the private key matching the given address can be decrypted with the given passphrase. The produced signature is in the [R || S || V] format where V is 0 or 1.
// 如果可以使用给定的密码短语解密与给定地址匹配的私钥，则 SignHashWithPassphrase 对哈希进行签名。生成的签名位于 [R || S || V] 格式，其中 V 为 0 或 1。
func (ks *KeyStore) SignHashWithPassphrase(a accounts.Account, passphrase string, hash []byte) (signature []byte, err error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key.PrivateKey)
	return crypto.Sign(hash, key.PrivateKey)
}

// SignTxWithPassphrase signs the transaction if the private key matching the given address can be decrypted with the given passphrase.
// 如果可以使用给定密码解密与给定地址匹配的私钥，则 SignTxWithPassphrase 对交易进行签名。
func (ks *KeyStore) SignTxWithPassphrase(a accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key.PrivateKey)
	// Depending on the presence of the chain ID, sign with or without replay protection.
	// 根据链 ID 的存在，使用或不使用重放保护进行签名。
	signer := types.LatestSignerForChainID(chainID)
	return types.SignTx(tx, signer, key.PrivateKey)
}

// Unlock unlocks the given account indefinitely.
// 解锁无限期地解锁给定帐户。
func (ks *KeyStore) Unlock(a accounts.Account, passphrase string) error {
	return ks.TimedUnlock(a, passphrase, 0)
}

// Lock removes the private key with the given address from memory.
// 锁定从内存中删除具有给定地址的私钥。
func (ks *KeyStore) Lock(addr common.Address) error {
	ks.mu.Lock()
	if unl, found := ks.unlocked[addr]; found {
		ks.mu.Unlock()
		ks.expire(addr, unl, time.Duration(0)*time.Nanosecond)
	} else {
		ks.mu.Unlock()
	}
	return nil
}

// TimedUnlock unlocks the given account with the passphrase. The account stays unlocked for the duration of timeout. A timeout of 0 unlocks the account until the program exits. The account must match a unique key file.
// TimedUnlock 使用密码解锁给定帐户。帐户在超时期间保持解锁状态。超时为 0 将解锁帐户，直到程序退出。该帐户必须与唯一的密钥文件匹配。
// If the account address is already unlocked for a duration, TimedUnlock extends or shortens the active unlock timeout. If the address was previously unlocked indefinitely the timeout is not altered.
// 如果账户地址已经解锁一段时间，TimedUnlock会延长或缩短主动解锁超时时间。如果地址之前已无限期解锁，则超时不会更改。
func (ks *KeyStore) TimedUnlock(a accounts.Account, passphrase string, timeout time.Duration) error {
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()
	u, found := ks.unlocked[a.Address]
	if found {
		if u.abort == nil {
			// The address was unlocked indefinitely, so unlocking it with a timeout would be confusing.
			// 该地址是无限期解锁的，因此超时解锁会很混乱。
			zeroKey(key.PrivateKey)
			return nil
		}
		// Terminate the expire goroutine and replace it below.
		// 终止expire goroutine并在下面替换它。
		close(u.abort)
	}
	if timeout > 0 {
		u = &unlocked{Key: key, abort: make(chan struct{})}
		go ks.expire(a.Address, u, timeout)
	} else {
		u = &unlocked{Key: key}
	}
	ks.unlocked[a.Address] = u
	return nil
}

// Find resolves the given account into a unique entry in the keystore.
// Find 将给定帐户解析为密钥库中的唯一条目。
func (ks *KeyStore) Find(a accounts.Account) (accounts.Account, error) {
	ks.cache.maybeReload()
	ks.cache.mu.Lock()
	a, err := ks.cache.find(a)
	ks.cache.mu.Unlock()
	return a, err
}

func (ks *KeyStore) getDecryptedKey(a accounts.Account, auth string) (accounts.Account, *Key, error) {
	a, err := ks.Find(a)
	if err != nil {
		return a, nil, err
	}
	key, err := ks.storage.GetKey(a.Address, a.URL.Path, auth)
	return a, key, err
}

func (ks *KeyStore) expire(addr common.Address, u *unlocked, timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-u.abort:
		// just quit
		// 退出吧
	case <-t.C:
		ks.mu.Lock()
		// only drop if it's still the same key instance that dropLater was launched with. we can check that using pointer equality because the map stores a new pointer every time the key is unlocked.
		// 仅当它仍然与 dropLater 启动时使用的密钥实例相同时才删除。我们可以使用指针相等来检查这一点，因为每次解锁密钥时映射都会存储一个新指针。
		if ks.unlocked[addr] == u {
			zeroKey(u.PrivateKey)
			delete(ks.unlocked, addr)
		}
		ks.mu.Unlock()
	}
}

// NewAccount generates a new key and stores it into the key directory, encrypting it with the passphrase.
// NewAccount 生成一个新密钥并将其存储到密钥目录中，并使用密码对其进行加密。
func (ks *KeyStore) NewAccount(passphrase string) (accounts.Account, error) {
	_, account, err := storeNewKey(ks.storage, crand.Reader, passphrase)
	if err != nil {
		return accounts.Account{}, err
	}
	// Add the account to the cache immediately rather than waiting for file system notifications to pick it up.
	// 立即将帐户添加到缓存中，而不是等待文件系统通知来获取它。
	ks.cache.add(account)
	ks.refreshWallets()
	return account, nil
}

// Export exports as a JSON key, encrypted with newPassphrase.
// 将导出导出为 JSON 密钥，并使用 newPassphrase 进行加密。
func (ks *KeyStore) Export(a accounts.Account, passphrase, newPassphrase string) (keyJSON []byte, err error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	var N, P int
	if store, ok := ks.storage.(*keyStorePassphrase); ok {
		N, P = store.scryptN, store.scryptP
	} else {
		N, P = StandardScryptN, StandardScryptP
	}
	return EncryptKey(key, newPassphrase, N, P)
}

// Import stores the given encrypted JSON key into the key directory.
// Import 将给定的加密 JSON 密钥存储到密钥目录中。
func (ks *KeyStore) Import(keyJSON []byte, passphrase, newPassphrase string) (accounts.Account, error) {
	key, err := DecryptKey(keyJSON, passphrase)
	if key != nil && key.PrivateKey != nil {
		defer zeroKey(key.PrivateKey)
	}
	if err != nil {
		return accounts.Account{}, err
	}
	ks.importMu.Lock()
	defer ks.importMu.Unlock()

	if ks.cache.hasAddress(key.Address) {
		return accounts.Account{
			Address: key.Address,
		}, ErrAccountAlreadyExists
	}
	return ks.importKey(key, newPassphrase)
}

// ImportECDSA stores the given key into the key directory, encrypting it with the passphrase.
// ImportECDSA 将给定密钥存储到密钥目录中，并使用密码对其进行加密。
func (ks *KeyStore) ImportECDSA(priv *ecdsa.PrivateKey, passphrase string) (accounts.Account, error) {
	ks.importMu.Lock()
	defer ks.importMu.Unlock()

	key := newKeyFromECDSA(priv)
	if ks.cache.hasAddress(key.Address) {
		return accounts.Account{
			Address: key.Address,
		}, ErrAccountAlreadyExists
	}
	return ks.importKey(key, passphrase)
}

func (ks *KeyStore) importKey(key *Key, passphrase string) (accounts.Account, error) {
	a := accounts.Account{Address: key.Address, URL: accounts.URL{Scheme: KeyStoreScheme, Path: ks.storage.JoinPath(keyFileName(key.Address))}}
	if err := ks.storage.StoreKey(a.URL.Path, key, passphrase); err != nil {
		return accounts.Account{}, err
	}
	ks.cache.add(a)
	ks.refreshWallets()
	return a, nil
}

// Update changes the passphrase of an existing account.
// 更新更改现有帐户的密码。
func (ks *KeyStore) Update(a accounts.Account, passphrase, newPassphrase string) error {
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}
	return ks.storage.StoreKey(a.URL.Path, key, newPassphrase)
}

// ImportPreSaleKey decrypts the given Ethereum presale wallet and stores a key file in the key directory. The key file is encrypted with the same passphrase.
// ImportPreSaleKey 解密给定的以太坊预售钱包，并将密钥文件存储在密钥目录中。密钥文件使用相同的密码进行加密。
func (ks *KeyStore) ImportPreSaleKey(keyJSON []byte, passphrase string) (accounts.Account, error) {
	a, _, err := importPreSaleKey(ks.storage, keyJSON, passphrase)
	if err != nil {
		return a, err
	}
	ks.cache.add(a)
	ks.refreshWallets()
	return a, nil
}

// isUpdating returns whether the event notification loop is running. This method is mainly meant for tests.
// isUpdating 返回事件通知循环是否正在运行。该方法主要用于测试。
func (ks *KeyStore) isUpdating() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.updating
}

// zeroKey zeroes a private key in memory.
// ZeroKey 将内存中的私钥归零。
func zeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	clear(b)
}


