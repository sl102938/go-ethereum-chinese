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

package keystore

import (
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// keystoreWallet implements the accounts.Wallet interface for the original keystore.
// keystoreWallet 实现原始密钥库的accounts.Wallet 接口。
type keystoreWallet struct {
	account  accounts.Account // Single account contained in this wallet // 该钱包中包含单个帐户
	keystore *KeyStore        // Keystore where the account originates from // 帐户来源的密钥库
}

// URL implements accounts.Wallet, returning the URL of the account within.
// URL 实现accounts.Wallet，返回其中帐户的URL。
func (w *keystoreWallet) URL() accounts.URL {
	return w.account.URL
}

// Status implements accounts.Wallet, returning whether the account held by the keystore wallet is unlocked or not.
// Status实现accounts.Wallet，返回keystore钱包持有的账户是否解锁。
func (w *keystoreWallet) Status() (string, error) {
	w.keystore.mu.RLock()
	defer w.keystore.mu.RUnlock()

	if _, ok := w.keystore.unlocked[w.account.Address]; ok {
		return "Unlocked", nil
	}
	return "Locked", nil
}

// Open implements accounts.Wallet, but is a noop for plain wallets since there is no connection or decryption step necessary to access the list of accounts.
// Open 实现了 account.Wallet，但对于普通钱包来说是无用的，因为访问帐户列表不需要连接或解密步骤。
func (w *keystoreWallet) Open(passphrase string) error { return nil }

// Close implements accounts.Wallet, but is a noop for plain wallets since there is no meaningful open operation.
// Close 实现了 account.Wallet，但对于普通钱包来说是无用的，因为没有有意义的打开操作。
func (w *keystoreWallet) Close() error { return nil }

// Accounts implements accounts.Wallet, returning an account list consisting of a single account that the plain keystore wallet contains.
// Accounts 实现 account.Wallet，返回一个由普通密钥库钱包包含的单个帐户组成的帐户列表。
func (w *keystoreWallet) Accounts() []accounts.Account {
	return []accounts.Account{w.account}
}

// Contains implements accounts.Wallet, returning whether a particular account is or is not wrapped by this wallet instance.
// 包含实现accounts.Wallet，返回特定帐户是否被此钱包实例包装。
func (w *keystoreWallet) Contains(account accounts.Account) bool {
	return account.Address == w.account.Address && (account.URL == (accounts.URL{}) || account.URL == w.account.URL)
}

// Derive implements accounts.Wallet, but is a noop for plain wallets since there is no notion of hierarchical account derivation for plain keystore accounts.
// Derive 实现了 account.Wallet，但对于普通钱包来说是无用的，因为普通密钥库帐户没有分层帐户派生的概念。
func (w *keystoreWallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	return accounts.Account{}, accounts.ErrNotSupported
}

// SelfDerive implements accounts.Wallet, but is a noop for plain wallets since there is no notion of hierarchical account derivation for plain keystore accounts.
// SelfDerive 实现accounts.Wallet，但对于普通钱包来说是无用的，因为普通密钥库帐户没有分层帐户派生的概念。
func (w *keystoreWallet) SelfDerive(bases []accounts.DerivationPath, chain ethereum.ChainStateReader) {
}

// signHash attempts to sign the given hash with the given account. If the wallet does not wrap this particular account, an error is returned to avoid account leakage (even though in theory we may be able to sign via our shared keystore backend).
// signHash 尝试使用给定帐户对给定哈希进行签名。如果钱包没有包装这个特定帐户，则会返回错误以避免帐户泄漏（即使理论上我们可以通过共享密钥库后端进行签名）。
func (w *keystoreWallet) signHash(account accounts.Account, hash []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	// 确保请求的帐户包含在
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	// 帐户似乎有效，请求密钥库签名
	return w.keystore.SignHash(account, hash)
}

// SignData signs keccak256(data). The mimetype parameter describes the type of data being signed.
// SignData 对 keccak256（数据）进行签名。 mimetype 参数描述了正在签名的数据的类型。
func (w *keystoreWallet) SignData(account accounts.Account, mimeType string, data []byte) ([]byte, error) {
	return w.signHash(account, crypto.Keccak256(data))
}

// SignDataWithPassphrase signs keccak256(data). The mimetype parameter describes the type of data being signed.
// SignDataWithPassphrase 对 keccak256（数据）进行签名。 mimetype 参数描述了正在签名的数据的类型。
func (w *keystoreWallet) SignDataWithPassphrase(account accounts.Account, passphrase, mimeType string, data []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	// 确保请求的帐户包含在
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	// 帐户似乎有效，请求密钥库签名
	return w.keystore.SignHashWithPassphrase(account, passphrase, crypto.Keccak256(data))
}

// SignText implements accounts.Wallet, attempting to sign the hash of the given text with the given account.
// SignText 实现accounts.Wallet，尝试使用给定帐户对给定文本的哈希进行签名。
func (w *keystoreWallet) SignText(account accounts.Account, text []byte) ([]byte, error) {
	return w.signHash(account, accounts.TextHash(text))
}

// SignTextWithPassphrase implements accounts.Wallet, attempting to sign the hash of the given text with the given account using passphrase as extra authentication.
// SignTextWithPassphrase 实现accounts.Wallet，尝试使用密码短语作为额外身份验证使用给定帐户对给定文本的哈希进行签名。
func (w *keystoreWallet) SignTextWithPassphrase(account accounts.Account, passphrase string, text []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	// 确保请求的帐户包含在
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	// 帐户似乎有效，请求密钥库签名
	return w.keystore.SignHashWithPassphrase(account, passphrase, accounts.TextHash(text))
}

// SignTx implements accounts.Wallet, attempting to sign the given transaction with the given account. If the wallet does not wrap this particular account, an error is returned to avoid account leakage (even though in theory we may be able to sign via our shared keystore backend).
// SignTx 实现accounts.Wallet，尝试使用给定帐户签署给定交易。如果钱包没有包装这个特定帐户，则会返回错误以避免帐户泄漏（即使理论上我们可以通过共享密钥库后端进行签名）。
func (w *keystoreWallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	// Make sure the requested account is contained within
	// 确保请求的帐户包含在
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	// 帐户似乎有效，请求密钥库签名
	return w.keystore.SignTx(account, tx, chainID)
}

// SignTxWithPassphrase implements accounts.Wallet, attempting to sign the given transaction with the given account using passphrase as extra authentication.
// SignTxWithPassphrase 实现accounts.Wallet，尝试使用密码短语作为额外身份验证使用给定帐户签署给定交易。
func (w *keystoreWallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	// Make sure the requested account is contained within
	// 确保请求的帐户包含在
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	// 帐户似乎有效，请求密钥库签名
	return w.keystore.SignTxWithPassphrase(account, passphrase, tx, chainID)
}


