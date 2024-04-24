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

// Package usbwallet implements support for USB hardware wallets.
package usbwallet

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/karalabe/hid"
)

// Maximum time between wallet health checks to detect USB unplugs.
// 钱包运行状况检查与检测 USB 拔出之间的最长时间。
const heartbeatCycle = time.Second

// Minimum time to wait between self derivation attempts, even it the user is requesting accounts like crazy.
// 自推导尝试之间等待的最短时间，即使用户疯狂地请求帐户。
const selfDeriveThrottling = time.Second

// driver defines the vendor specific functionality hardware wallets instances must implement to allow using them with the wallet lifecycle management.
// 驱动程序定义了硬件钱包实例必须实现的供应商特定功能，以允许将它们与钱包生命周期管理一起使用。
type driver interface {
	// Status returns a textual status to aid the user in the current state of the wallet. It also returns an error indicating any failure the wallet might have encountered.
	// Status 返回文本状态以帮助用户了解钱包的当前状态。它还返回一个错误，指示钱包可能遇到的任何故障。
	Status() (string, error)

	// Open initializes access to a wallet instance. The passphrase parameter may or may not be used by the implementation of a particular wallet instance.
	// Open 初始化对钱包实例的访问。特定钱包实例的实现可能会或可能不会使用密码参数。
	Open(device io.ReadWriter, passphrase string) error

	// Close releases any resources held by an open wallet instance.
	// 关闭会释放打开的钱包实例持有的所有资源。
	Close() error

	// Heartbeat performs a sanity check against the hardware wallet to see if it is still online and healthy.
	// Heartbeat 对硬件钱包执行健全性检查，看看它是否仍然在线且健康。
	Heartbeat() error

	// Derive sends a derivation request to the USB device and returns the Ethereum address located on that path.
	// Derive 向 USB 设备发送派生请求并返回位于该路径上的以太坊地址。
	Derive(path accounts.DerivationPath) (common.Address, error)

	// SignTx sends the transaction to the USB device and waits for the user to confirm or deny the transaction.
	// SignTx 将事务发送到 USB 设备并等待用户确认或拒绝事务。
	SignTx(path accounts.DerivationPath, tx *types.Transaction, chainID *big.Int) (common.Address, *types.Transaction, error)

	SignTypedMessage(path accounts.DerivationPath, messageHash []byte, domainHash []byte) ([]byte, error)
}

// wallet represents the common functionality shared by all USB hardware wallets to prevent reimplementing the same complex maintenance mechanisms for different vendors.
// wallet 代表所有 USB 硬件钱包共享的通用功能，以防止为不同供应商重新实现相同的复杂维护机制。
type wallet struct {
	hub    *Hub          // USB hub scanning // USB集线器扫描
	driver driver        // Hardware implementation of the low level device operations // 低级设备操作的硬件实现
	url    *accounts.URL // Textual URL uniquely identifying this wallet // 唯一标识该钱包的文本 URL

	info   hid.DeviceInfo // Known USB device infos about the wallet // 有关钱包的已知 USB 设备信息
	device hid.Device     // USB device advertising itself as a hardware wallet // USB 设备将自己宣传为硬件钱包

	accounts []accounts.Account                         // List of derive accounts pinned on the hardware wallet // 固定在硬件钱包上的派生帐户列表
	paths    map[common.Address]accounts.DerivationPath // Known derivation paths for signing operations // 签名操作的已知派生路径

	deriveNextPaths []accounts.DerivationPath // Next derivation paths for account auto-discovery (multiple bases supported) // 帐户自动发现的下一个派生路径（支持多个基础）
	deriveNextAddrs []common.Address          // Next derived account addresses for auto-discovery (multiple bases supported) // 用于自动发现的下一个派生帐户地址（支持多个基础）
	deriveChain     ethereum.ChainStateReader // Blockchain state reader to discover used account with // 区块链状态阅读器可发现已使用的帐户
	deriveReq       chan chan struct{}        // Channel to request a self-derivation on // 请求自推导的通道
	deriveQuit      chan chan error           // Channel to terminate the self-deriver with // 终止自导出的通道

	healthQuit chan chan error

	// Locking a hardware wallet is a bit special. Since hardware devices are lower performing, any communication with them might take a non negligible amount of time. Worse still, waiting for user confirmation can take arbitrarily long, but exclusive communication must be upheld during. Locking the entire wallet in the mean time however would stall any parts of the system that don't want to communicate, just read some state (e.g. list the accounts).
	// 锁定硬件钱包有点特殊。由于硬件设备的性能较低，因此与它们的任何通信都可能花费不可忽略的时间。更糟糕的是，等待用户确认可能需要任意长的时间，但在此期间必须保持独占通信。然而，同时锁定整个钱包会阻止系统中不想通信的任何部分，只需读取一些状态（例如列出帐户）。
	// As such, a hardware wallet needs two locks to function correctly. A state lock can be used to protect the wallet's software-side internal state, which must not be held exclusively during hardware communication. A communication lock can be used to achieve exclusive access to the device itself, this one however should allow "skipping" waiting for operations that might want to use the device, but can live without too (e.g. account self-derivation).
	// 因此，硬件钱包需要两把锁才能正常运行。状态锁可用于保护钱包的软件端内部状态，该状态不能在硬件通信期间独占保存。通信锁可用于实现对设备本身的独占访问，但是该通信锁应该允许“跳过”等待可能想要使用该设备但也可以不使用的操作（例如帐户自派生）。
	// Since we have two locks, it's important to know how to properly use them:
	// 由于我们有两把锁，因此了解如何正确使用它们很重要：
	//   - Communication requires the `device` to not change, so obtaining the
	//   - 通信要求“设备”不改变，因此获取
	//     commsLock should be done after having a stateLock.
	//     commsLock 应该在拥有 stateLock 之后进行。
	//   - Communication must not disable read access to the wallet state, so it
	//   - 通信不得禁用对钱包状态的读取访问，因此
	//     must only ever hold a *read* lock to stateLock.
	//     必须只持有对 stateLock 的“读”锁。
	commsLock chan struct{} // Mutex (buf=1) for the USB comms without keeping the state locked // 用于 USB 通信的互斥锁 (buf=1)，无需保持状态锁定
	stateLock sync.RWMutex  // Protects read and write access to the wallet struct fields // 保护对钱包结构字段的读写访问

	log log.Logger // Contextual logger to tag the base with its id // 上下文记录器用其 id 标记底座
}

// URL implements accounts.Wallet, returning the URL of the USB hardware device.
// URL实现accounts.Wallet，返回USB硬件设备的URL。
func (w *wallet) URL() accounts.URL {
	return *w.url // Immutable, no need for a lock // 不可变，不需要锁
}

// Status implements accounts.Wallet, returning a custom status message from the underlying vendor-specific hardware wallet implementation.
// Status 实现 account.Wallet，从底层特定于供应商的硬件钱包实现返回自定义状态消息。
func (w *wallet) Status() (string, error) {
	w.stateLock.RLock() // No device communication, state lock is enough // 没有设备通信，状态锁就足够了
	defer w.stateLock.RUnlock()

	status, failure := w.driver.Status()
	if w.device == nil {
		return "Closed", failure
	}
	return status, failure
}

// Open implements accounts.Wallet, attempting to open a USB connection to the hardware wallet.
// Open 实现 account.Wallet，尝试打开与硬件钱包的 USB 连接。
func (w *wallet) Open(passphrase string) error {
	w.stateLock.Lock() // State lock is enough since there's no connection yet at this point // 状态锁就足够了，因为此时还没有连接
	defer w.stateLock.Unlock()

	// If the device was already opened once, refuse to try again
	// 如果设备已打开过一次，请拒绝重试
	if w.paths != nil {
		return accounts.ErrWalletAlreadyOpen
	}
	// Make sure the actual device connection is done only once
	// 确保实际设备连接仅完成一次
	if w.device == nil {
		device, err := w.info.Open()
		if err != nil {
			return err
		}
		w.device = device
		w.commsLock = make(chan struct{}, 1)
		w.commsLock <- struct{}{} // Enable lock // 启用锁定
	}
	// Delegate device initialization to the underlying driver
	// 将设备初始化委托给底层驱动程序
	if err := w.driver.Open(w.device, passphrase); err != nil {
		return err
	}
	// Connection successful, start life-cycle management
	// 连接成功，启动生命周期管理
	w.paths = make(map[common.Address]accounts.DerivationPath)

	w.deriveReq = make(chan chan struct{})
	w.deriveQuit = make(chan chan error)
	w.healthQuit = make(chan chan error)

	go w.heartbeat()
	go w.selfDerive()

	// Notify anyone listening for wallet events that a new device is accessible
	// 通知监听钱包事件的任何人有新设备可以访问
	go w.hub.updateFeed.Send(accounts.WalletEvent{Wallet: w, Kind: accounts.WalletOpened})

	return nil
}

// heartbeat is a health check loop for the USB wallets to periodically verify whether they are still present or if they malfunctioned.
// heartbeat 是 USB 钱包的健康检查循环，用于定期验证它们是否仍然存在或是否出现故障。
func (w *wallet) heartbeat() {
	w.log.Debug("USB wallet health-check started")
	defer w.log.Debug("USB wallet health-check stopped")

	// Execute heartbeat checks until termination or error
	// 执行心跳检查，直到终止或出错
	var (
		errc chan error
		err  error
	)
	for errc == nil && err == nil {
		// Wait until termination is requested or the heartbeat cycle arrives
		// 等待直到请求终止或心跳周期到达
		select {
		case errc = <-w.healthQuit:
			// Termination requested
			// 请求终止
			continue
		case <-time.After(heartbeatCycle):
			// Heartbeat time
			// 心跳时间
		}
		// Execute a tiny data exchange to see responsiveness
		// 执行微小的数据交换以查看响应能力
		w.stateLock.RLock()
		if w.device == nil {
			// Terminated while waiting for the lock
			// 等待锁时终止
			w.stateLock.RUnlock()
			continue
		}
		<-w.commsLock // Don't lock state while resolving version // 解析版本时不要锁定状态
		err = w.driver.Heartbeat()
		w.commsLock <- struct{}{}
		w.stateLock.RUnlock()

		if err != nil {
			w.stateLock.Lock() // Lock state to tear the wallet down // 锁定状态撕下钱包
			w.close()
			w.stateLock.Unlock()
		}
		// Ignore non hardware related errors
		// 忽略与硬件无关的错误
		err = nil
	}
	// In case of error, wait for termination
	// 如果出现错误，等待终止
	if err != nil {
		w.log.Debug("USB wallet health-check failed", "err", err)
		errc = <-w.healthQuit
	}
	errc <- err
}

// Close implements accounts.Wallet, closing the USB connection to the device.
// 关闭实现accounts.Wallet，关闭与设备的USB连接。
func (w *wallet) Close() error {
	// Ensure the wallet was opened
	// 确保钱包已打开
	w.stateLock.RLock()
	hQuit, dQuit := w.healthQuit, w.deriveQuit
	w.stateLock.RUnlock()

	// Terminate the health checks
	// 终止健康检查
	var herr error
	if hQuit != nil {
		errc := make(chan error)
		hQuit <- errc
		herr = <-errc // Save for later, we *must* close the USB // 留着以后用，我们*必须*关闭 USB
	}
	// Terminate the self-derivations
	// 终止自推导
	var derr error
	if dQuit != nil {
		errc := make(chan error)
		dQuit <- errc
		derr = <-errc // Save for later, we *must* close the USB // 留着以后用，我们*必须*关闭 USB
	}
	// Terminate the device connection
	// 终止设备连接
	w.stateLock.Lock()
	defer w.stateLock.Unlock()

	w.healthQuit = nil
	w.deriveQuit = nil
	w.deriveReq = nil

	if err := w.close(); err != nil {
		return err
	}
	if herr != nil {
		return herr
	}
	return derr
}

// close is the internal wallet closer that terminates the USB connection and resets all the fields to their defaults.
// close 是内部钱包关闭器，用于终止 USB 连接并将所有字段重置为默认值。
// Note, close assumes the state lock is held!
// 注意，close 假设状态锁已被持有！
func (w *wallet) close() error {
	// Allow duplicate closes, especially for health-check failures
	// 允许重复关闭，特别是对于运行状况检查失败的情况
	if w.device == nil {
		return nil
	}
	// Close the device, clear everything, then return
	// 关闭设备，清除所有内容，然后返回
	w.device.Close()
	w.device = nil

	w.accounts, w.paths = nil, nil
	return w.driver.Close()
}

// Accounts implements accounts.Wallet, returning the list of accounts pinned to the USB hardware wallet. If self-derivation was enabled, the account list is periodically expanded based on current chain state.
// Accounts 实现 account.Wallet，返回固定到 USB 硬件钱包的帐户列表。如果启用自衍生，则账户列表会根据当前链状态定期扩展。
func (w *wallet) Accounts() []accounts.Account {
	// Attempt self-derivation if it's running
	// 如果正在运行，请尝试自推导
	reqc := make(chan struct{}, 1)
	select {
	case w.deriveReq <- reqc:
		// Self-derivation request accepted, wait for it
		// 自推请求已接受，等待
		<-reqc
	default:
		// Self-derivation offline, throttled or busy, skip
		// 自推导离线、节流或繁忙，跳过
	}
	// Return whatever account list we ended up with
	// 返回我们最终得到的任何帐户列表
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	cpy := make([]accounts.Account, len(w.accounts))
	copy(cpy, w.accounts)
	return cpy
}

// selfDerive is an account derivation loop that upon request attempts to find new non-zero accounts.
// selfDerive 是一个帐户派生循环，根据请求尝试查找新的非零帐户。
func (w *wallet) selfDerive() {
	w.log.Debug("USB wallet self-derivation started")
	defer w.log.Debug("USB wallet self-derivation stopped")

	// Execute self-derivations until termination or error
	// 执行自推导直到终止或出错
	var (
		reqc chan struct{}
		errc chan error
		err  error
	)
	for errc == nil && err == nil {
		// Wait until either derivation or termination is requested
		// 等待直到请求派生或终止
		select {
		case errc = <-w.deriveQuit:
			// Termination requested
			// 请求终止
			continue
		case reqc = <-w.deriveReq:
			// Account discovery requested
			// 已请求帐户发现
		}
		// Derivation needs a chain and device access, skip if either unavailable
		// 推导需要链和设备访问，如果其中一个不可用则跳过
		w.stateLock.RLock()
		if w.device == nil || w.deriveChain == nil {
			w.stateLock.RUnlock()
			reqc <- struct{}{}
			continue
		}
		select {
		case <-w.commsLock:
		default:
			w.stateLock.RUnlock()
			reqc <- struct{}{}
			continue
		}
		// Device lock obtained, derive the next batch of accounts
		// 获取设备锁，导出下一批账户
		var (
			accs  []accounts.Account
			paths []accounts.DerivationPath

			nextPaths = append([]accounts.DerivationPath{}, w.deriveNextPaths...)
			nextAddrs = append([]common.Address{}, w.deriveNextAddrs...)

			context = context.Background()
		)
		for i := 0; i < len(nextAddrs); i++ {
			for empty := false; !empty; {
				// Retrieve the next derived Ethereum account
				// 检索下一个派生的以太坊帐户
				if nextAddrs[i] == (common.Address{}) {
					if nextAddrs[i], err = w.driver.Derive(nextPaths[i]); err != nil {
						w.log.Warn("USB wallet account derivation failed", "err", err)
						break
					}
				}
				// Check the account's status against the current chain state
				// 根据当前链状态检查账户状态
				var (
					balance *big.Int
					nonce   uint64
				)
				balance, err = w.deriveChain.BalanceAt(context, nextAddrs[i], nil)
				if err != nil {
					w.log.Warn("USB wallet balance retrieval failed", "err", err)
					break
				}
				nonce, err = w.deriveChain.NonceAt(context, nextAddrs[i], nil)
				if err != nil {
					w.log.Warn("USB wallet nonce retrieval failed", "err", err)
					break
				}
				// We've just self-derived a new account, start tracking it locally unless the account was empty.
				// 我们刚刚自行派生了一个新帐户，开始在本地跟踪它，除非该帐户为空。
				path := make(accounts.DerivationPath, len(nextPaths[i]))
				copy(path[:], nextPaths[i][:])
				if balance.Sign() == 0 && nonce == 0 {
					empty = true
					// If it indeed was empty, make a log output for it anyway. In the case of legacy-ledger, the first account on the legacy-path will be shown to the user, even if we don't actively track it
					// 如果它确实是空的，无论如何都要为其输出日志。对于旧账本，旧路径上的第一个帐户将向用户显示，即使我们不主动跟踪它
					if i < len(nextAddrs)-1 {
						w.log.Info("Skipping tracking first account on legacy path, use personal.deriveAccount(<url>,<path>, false) to track",
							"path", path, "address", nextAddrs[i])
						break
					}
				}
				paths = append(paths, path)
				account := accounts.Account{
					Address: nextAddrs[i],
					URL:     accounts.URL{Scheme: w.url.Scheme, Path: fmt.Sprintf("%s/%s", w.url.Path, path)},
				}
				accs = append(accs, account)

				// Display a log message to the user for new (or previously empty accounts)
				// 向用户显示新帐户（或以前为空帐户）的日志消息
				if _, known := w.paths[nextAddrs[i]]; !known || (!empty && nextAddrs[i] == w.deriveNextAddrs[i]) {
					w.log.Info("USB wallet discovered new account", "address", nextAddrs[i], "path", path, "balance", balance, "nonce", nonce)
				}
				// Fetch the next potential account
				// 获取下一个潜在帐户
				if !empty {
					nextAddrs[i] = common.Address{}
					nextPaths[i][len(nextPaths[i])-1]++
				}
			}
		}
		// Self derivation complete, release device lock
		// 自推导完成，释放设备锁
		w.commsLock <- struct{}{}
		w.stateLock.RUnlock()

		// Insert any accounts successfully derived
		// 插入任何成功派生的帐户
		w.stateLock.Lock()
		for i := 0; i < len(accs); i++ {
			if _, ok := w.paths[accs[i].Address]; !ok {
				w.accounts = append(w.accounts, accs[i])
				w.paths[accs[i].Address] = paths[i]
			}
		}
		// Shift the self-derivation forward TODO(karalabe): don't overwrite changes from wallet.SelfDerive
		// 向前移动自推导 TODO(karalabe)：不要覆盖 wallet.SelfDerive 中的更改
		w.deriveNextAddrs = nextAddrs
		w.deriveNextPaths = nextPaths
		w.stateLock.Unlock()

		// Notify the user of termination and loop after a bit of time (to avoid trashing)
		// 通知用户终止并在一段时间后循环（以避免垃圾）
		reqc <- struct{}{}
		if err == nil {
			select {
			case errc = <-w.deriveQuit:
				// Termination requested, abort
				// 请求终止，中止
			case <-time.After(selfDeriveThrottling):
				// Waited enough, willing to self-derive again
				// 等够了愿意再次自生
			}
		}
	}
	// In case of error, wait for termination
	// 如果出现错误，等待终止
	if err != nil {
		w.log.Debug("USB wallet self-derivation failed", "err", err)
		errc = <-w.deriveQuit
	}
	errc <- err
}

// Contains implements accounts.Wallet, returning whether a particular account is or is not pinned into this wallet instance. Although we could attempt to resolve unpinned accounts, that would be an non-negligible hardware operation.
// 包含实现accounts.Wallet，返回特定帐户是否固定到此钱包实例中。尽管我们可以尝试解决未固定的帐户问题，但这将是一项不可忽视的硬件操作。
func (w *wallet) Contains(account accounts.Account) bool {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	_, exists := w.paths[account.Address]
	return exists
}

// Derive implements accounts.Wallet, deriving a new account at the specific derivation path. If pin is set to true, the account will be added to the list of tracked accounts.
// Derive实现accounts.Wallet，在特定的派生路径上派生出一个新的账户。如果 pin 设置为 true，该帐户将被添加到跟踪帐户列表中。
func (w *wallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	// Try to derive the actual account and update its URL if successful
	// 尝试派生实际帐户并更新其 URL（如果成功）
	w.stateLock.RLock() // Avoid device disappearing during derivation // 避免设备在派生过程中消失

	if w.device == nil {
		w.stateLock.RUnlock()
		return accounts.Account{}, accounts.ErrWalletClosed
	}
	<-w.commsLock // Avoid concurrent hardware access // 避免并发硬件访问
	address, err := w.driver.Derive(path)
	w.commsLock <- struct{}{}

	w.stateLock.RUnlock()

	// If an error occurred or no pinning was requested, return
	// 如果发生错误或未请求固定，则返回
	if err != nil {
		return accounts.Account{}, err
	}
	account := accounts.Account{
		Address: address,
		URL:     accounts.URL{Scheme: w.url.Scheme, Path: fmt.Sprintf("%s/%s", w.url.Path, path)},
	}
	if !pin {
		return account, nil
	}
	// Pinning needs to modify the state
	// Pinning需要修改状态
	w.stateLock.Lock()
	defer w.stateLock.Unlock()

	if w.device == nil {
		return accounts.Account{}, accounts.ErrWalletClosed
	}

	if _, ok := w.paths[address]; !ok {
		w.accounts = append(w.accounts, account)
		w.paths[address] = make(accounts.DerivationPath, len(path))
		copy(w.paths[address], path)
	}
	return account, nil
}

// SelfDerive sets a base account derivation path from which the wallet attempts to discover non zero accounts and automatically add them to list of tracked accounts.
// SelfDerive 设置基本帐户派生路径，钱包尝试从中发现非零帐户并自动将它们添加到跟踪帐户列表中。
// Note, self derivation will increment the last component of the specified path opposed to descending into a child path to allow discovering accounts starting from non zero components.
// 请注意，自派生将增加指定路径的最后一个组件，而不是下降到子路径，以允许从非零组件开始发现帐户。
// Some hardware wallets switched derivation paths through their evolution, so this method supports providing multiple bases to discover old user accounts too. Only the last base will be used to derive the next empty account.
// 一些硬件钱包在演变过程中改变了派生路径，因此该方法也支持提供多个基础来发现旧用户帐户。仅最后一个基数将用于派生下一个空帐户。
// You can disable automatic account discovery by calling SelfDerive with a nil chain state reader.
// 您可以通过使用 nil 链状态读取器调用 SelfDerive 来禁用自动帐户发现。
func (w *wallet) SelfDerive(bases []accounts.DerivationPath, chain ethereum.ChainStateReader) {
	w.stateLock.Lock()
	defer w.stateLock.Unlock()

	w.deriveNextPaths = make([]accounts.DerivationPath, len(bases))
	for i, base := range bases {
		w.deriveNextPaths[i] = make(accounts.DerivationPath, len(base))
		copy(w.deriveNextPaths[i][:], base[:])
	}
	w.deriveNextAddrs = make([]common.Address, len(bases))
	w.deriveChain = chain
}

// signHash implements accounts.Wallet, however signing arbitrary data is not supported for hardware wallets, so this method will always return an error.
// signHash 实现了 account.Wallet，但是硬件钱包不支持对任意数据进行签名，因此此方法将始终返回错误。
func (w *wallet) signHash(account accounts.Account, hash []byte) ([]byte, error) {
	return nil, accounts.ErrNotSupported
}

// SignData signs keccak256(data). The mimetype parameter describes the type of data being signed
// SignData 对 keccak256（数据）进行签名。 mimetype 参数描述了被签名的数据类型
func (w *wallet) SignData(account accounts.Account, mimeType string, data []byte) ([]byte, error) {
	// Unless we are doing 712 signing, simply dispatch to signHash
	// 除非我们正在进行 712 签名，否则只需发送到 SignHash
	if !(mimeType == accounts.MimetypeTypedData && len(data) == 66 && data[0] == 0x19 && data[1] == 0x01) {
		return w.signHash(account, crypto.Keccak256(data))
	}

	// dispatch to 712 signing if the mimetype is TypedData and the format matches
	// 如果 mimetype 是 TypedData 并且格式匹配，则分派到 712 签名
	w.stateLock.RLock() // Comms have own mutex, this is for the state fields // 通信有自己的互斥锁，这是用于状态字段的
	defer w.stateLock.RUnlock()

	// If the wallet is closed, abort
	// 如果钱包关闭，则中止
	if w.device == nil {
		return nil, accounts.ErrWalletClosed
	}
	// Make sure the requested account is contained within
	// 确保请求的帐户包含在
	path, ok := w.paths[account.Address]
	if !ok {
		return nil, accounts.ErrUnknownAccount
	}
	// All infos gathered and metadata checks out, request signing
	// 收集所有信息并检查元数据，请求签名
	<-w.commsLock
	defer func() { w.commsLock <- struct{}{} }()

	// Ensure the device isn't screwed with while user confirmation is pending TODO(karalabe): remove if hotplug lands on Windows
	// 确保设备在等待用户确认时没有被拧紧 TODO(karalabe)：如果热插拔安装在 Windows 上，请删除
	w.hub.commsLock.Lock()
	w.hub.commsPend++
	w.hub.commsLock.Unlock()

	defer func() {
		w.hub.commsLock.Lock()
		w.hub.commsPend--
		w.hub.commsLock.Unlock()
	}()
	// Sign the transaction
	// 签署交易
	signature, err := w.driver.SignTypedMessage(path, data[2:34], data[34:66])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// SignDataWithPassphrase implements accounts.Wallet, attempting to sign the given data with the given account using passphrase as extra authentication. Since USB wallets don't rely on passphrases, these are silently ignored.
// SignDataWithPassphrase 实现accounts.Wallet，尝试使用密码短语作为额外身份验证使用给定帐户对给定数据进行签名。由于 USB 钱包不依赖密码，因此这些密码会被悄悄忽略。
func (w *wallet) SignDataWithPassphrase(account accounts.Account, passphrase, mimeType string, data []byte) ([]byte, error) {
	return w.SignData(account, mimeType, data)
}

func (w *wallet) SignText(account accounts.Account, text []byte) ([]byte, error) {
	return w.signHash(account, accounts.TextHash(text))
}

// SignTx implements accounts.Wallet. It sends the transaction over to the Ledger wallet to request a confirmation from the user. It returns either the signed transaction or a failure if the user denied the transaction.
// SignTx实现了accounts.Wallet。它将交易发送到 Ledger 钱包以请求用户确认。如果用户拒绝交易，它会返回已签名的交易或失败。
// Note, if the version of the Ethereum application running on the Ledger wallet is too old to sign EIP-155 transactions, but such is requested nonetheless, an error will be returned opposed to silently signing in Homestead mode.
// 请注意，如果 Ledger 钱包上运行的以太坊应用程序版本太旧，无法签署 EIP-155 交易，但尽管如此，仍会请求这样做，则会返回错误，而不是在 Homestead 模式下静默签名。
func (w *wallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	w.stateLock.RLock() // Comms have own mutex, this is for the state fields // 通信有自己的互斥锁，这是用于状态字段的
	defer w.stateLock.RUnlock()

	// If the wallet is closed, abort
	// 如果钱包关闭，则中止
	if w.device == nil {
		return nil, accounts.ErrWalletClosed
	}
	// Make sure the requested account is contained within
	// 确保请求的帐户包含在
	path, ok := w.paths[account.Address]
	if !ok {
		return nil, accounts.ErrUnknownAccount
	}
	// All infos gathered and metadata checks out, request signing
	// 收集所有信息并检查元数据，请求签名
	<-w.commsLock
	defer func() { w.commsLock <- struct{}{} }()

	// Ensure the device isn't screwed with while user confirmation is pending TODO(karalabe): remove if hotplug lands on Windows
	// 确保设备在等待用户确认时没有被拧紧 TODO(karalabe)：如果热插拔安装在 Windows 上，请删除
	w.hub.commsLock.Lock()
	w.hub.commsPend++
	w.hub.commsLock.Unlock()

	defer func() {
		w.hub.commsLock.Lock()
		w.hub.commsPend--
		w.hub.commsLock.Unlock()
	}()
	// Sign the transaction and verify the sender to avoid hardware fault surprises
	// 签署交易并验证发送者以避免意外的硬件故障
	sender, signed, err := w.driver.SignTx(path, tx, chainID)
	if err != nil {
		return nil, err
	}
	if sender != account.Address {
		return nil, fmt.Errorf("signer mismatch: expected %s, got %s", account.Address.Hex(), sender.Hex())
	}
	return signed, nil
}

// SignTextWithPassphrase implements accounts.Wallet, however signing arbitrary data is not supported for Ledger wallets, so this method will always return an error.
// SignTextWithPassphrase 实现了 account.Wallet，但是 Ledger 钱包不支持对任意数据进行签名，因此此方法将始终返回错误。
func (w *wallet) SignTextWithPassphrase(account accounts.Account, passphrase string, text []byte) ([]byte, error) {
	return w.SignText(account, accounts.TextHash(text))
}

// SignTxWithPassphrase implements accounts.Wallet, attempting to sign the given transaction with the given account using passphrase as extra authentication. Since USB wallets don't rely on passphrases, these are silently ignored.
// SignTxWithPassphrase 实现accounts.Wallet，尝试使用密码短语作为额外身份验证使用给定帐户签署给定交易。由于 USB 钱包不依赖密码，因此这些密码会被悄悄忽略。
func (w *wallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return w.SignTx(account, tx, chainID)
}


