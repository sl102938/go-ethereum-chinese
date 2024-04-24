// Copyright 2016 The go-ethereum Authors
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

package bind

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/external"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

// ErrNoChainID is returned whenever the user failed to specify a chain id.
// 每当用户未能指定链 ID 时，就会返回 ErrNoChainID。
var ErrNoChainID = errors.New("no chain id specified")

// ErrNotAuthorized is returned when an account is not properly unlocked.
// 账户未正确解锁时返回ErrNotAuthorized。
var ErrNotAuthorized = errors.New("not authorized to sign this account")

// NewTransactor is a utility method to easily create a transaction signer from an encrypted json key stream and the associated passphrase.
// NewTransactor 是一种实用方法，可根据加密的 json 密钥流和关联的密码轻松创建交易签名者。
// Deprecated: Use NewTransactorWithChainID instead.
// 已弃用：改用 NewTransactorWithChainID。
func NewTransactor(keyin io.Reader, passphrase string) (*TransactOpts, error) {
	log.Warn("WARNING: NewTransactor has been deprecated in favour of NewTransactorWithChainID")
	json, err := io.ReadAll(keyin)
	if err != nil {
		return nil, err
	}
	key, err := keystore.DecryptKey(json, passphrase)
	if err != nil {
		return nil, err
	}
	return NewKeyedTransactor(key.PrivateKey), nil
}

// NewKeyStoreTransactor is a utility method to easily create a transaction signer from a decrypted key from a keystore.
// NewKeyStoreTransactor 是一种实用方法，可根据密钥库中的解密密钥轻松创建交易签名者。
// Deprecated: Use NewKeyStoreTransactorWithChainID instead.
// 已弃用：改用 NewKeyStoreTransactorWithChainID。
func NewKeyStoreTransactor(keystore *keystore.KeyStore, account accounts.Account) (*TransactOpts, error) {
	log.Warn("WARNING: NewKeyStoreTransactor has been deprecated in favour of NewTransactorWithChainID")
	signer := types.HomesteadSigner{}
	return &TransactOpts{
		From: account.Address,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if address != account.Address {
				return nil, ErrNotAuthorized
			}
			signature, err := keystore.SignHash(account, signer.Hash(tx).Bytes())
			if err != nil {
				return nil, err
			}
			return tx.WithSignature(signer, signature)
		},
		Context: context.Background(),
	}, nil
}

// NewKeyedTransactor is a utility method to easily create a transaction signer from a single private key.
// NewKeyedTransactor 是一种实用方法，可以轻松地从单个私钥创建交易签名者。
// Deprecated: Use NewKeyedTransactorWithChainID instead.
// 已弃用：改用 NewKeyedTransactorWithChainID。
func NewKeyedTransactor(key *ecdsa.PrivateKey) *TransactOpts {
	log.Warn("WARNING: NewKeyedTransactor has been deprecated in favour of NewKeyedTransactorWithChainID")
	keyAddr := crypto.PubkeyToAddress(key.PublicKey)
	signer := types.HomesteadSigner{}
	return &TransactOpts{
		From: keyAddr,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if address != keyAddr {
				return nil, ErrNotAuthorized
			}
			signature, err := crypto.Sign(signer.Hash(tx).Bytes(), key)
			if err != nil {
				return nil, err
			}
			return tx.WithSignature(signer, signature)
		},
		Context: context.Background(),
	}
}

// NewTransactorWithChainID is a utility method to easily create a transaction signer from an encrypted json key stream and the associated passphrase.
// NewTransactorWithChainID 是一种实用方法，可根据加密的 json 密钥流和关联的密码轻松创建交易签名者。
func NewTransactorWithChainID(keyin io.Reader, passphrase string, chainID *big.Int) (*TransactOpts, error) {
	json, err := io.ReadAll(keyin)
	if err != nil {
		return nil, err
	}
	key, err := keystore.DecryptKey(json, passphrase)
	if err != nil {
		return nil, err
	}
	return NewKeyedTransactorWithChainID(key.PrivateKey, chainID)
}

// NewKeyStoreTransactorWithChainID is a utility method to easily create a transaction signer from a decrypted key from a keystore.
// NewKeyStoreTransactorWithChainID 是一种实用方法，可根据密钥库中的解密密钥轻松创建交易签名者。
func NewKeyStoreTransactorWithChainID(keystore *keystore.KeyStore, account accounts.Account, chainID *big.Int) (*TransactOpts, error) {
	if chainID == nil {
		return nil, ErrNoChainID
	}
	signer := types.LatestSignerForChainID(chainID)
	return &TransactOpts{
		From: account.Address,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if address != account.Address {
				return nil, ErrNotAuthorized
			}
			signature, err := keystore.SignHash(account, signer.Hash(tx).Bytes())
			if err != nil {
				return nil, err
			}
			return tx.WithSignature(signer, signature)
		},
		Context: context.Background(),
	}, nil
}

// NewKeyedTransactorWithChainID is a utility method to easily create a transaction signer from a single private key.
// NewKeyedTransactorWithChainID 是一种实用方法，可以轻松地从单个私钥创建交易签名者。
func NewKeyedTransactorWithChainID(key *ecdsa.PrivateKey, chainID *big.Int) (*TransactOpts, error) {
	if chainID == nil {
		return nil, ErrNoChainID
	}
	keyAddr := crypto.PubkeyToAddress(key.PublicKey)
	signer := types.LatestSignerForChainID(chainID)
	return &TransactOpts{
		From: keyAddr,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if address != keyAddr {
				return nil, ErrNotAuthorized
			}
			signature, err := crypto.Sign(signer.Hash(tx).Bytes(), key)
			if err != nil {
				return nil, err
			}
			return tx.WithSignature(signer, signature)
		},
		Context: context.Background(),
	}, nil
}

// NewClefTransactor is a utility method to easily create a transaction signer with a clef backend.
// NewClefTransactor 是一种实用方法，可轻松创建具有 clef 后端的交易签名者。
func NewClefTransactor(clef *external.ExternalSigner, account accounts.Account) *TransactOpts {
	return &TransactOpts{
		From: account.Address,
		Signer: func(address common.Address, transaction *types.Transaction) (*types.Transaction, error) {
			if address != account.Address {
				return nil, ErrNotAuthorized
			}
			return clef.SignTx(account, transaction, nil) // Clef enforces its own chain id // Clef 强制执行自己的链 ID
		},
		Context: context.Background(),
	}
}


