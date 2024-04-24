// Copyright 2019 The go-ethereum Authors
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

package external

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

type ExternalBackend struct {
	signers []accounts.Wallet
}

func (eb *ExternalBackend) Wallets() []accounts.Wallet {
	return eb.signers
}

func NewExternalBackend(endpoint string) (*ExternalBackend, error) {
	signer, err := NewExternalSigner(endpoint)
	if err != nil {
		return nil, err
	}
	return &ExternalBackend{
		signers: []accounts.Wallet{signer},
	}, nil
}

func (eb *ExternalBackend) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	return event.NewSubscription(func(quit <-chan struct{}) error {
		<-quit
		return nil
	})
}

// ExternalSigner provides an API to interact with an external signer (clef) It proxies request to the external signer while forwarding relevant request headers
// ExternalSigner 提供与外部签名者（clef）交互的 API，它在转发相关请求标头的同时将请求代理给外部签名者
type ExternalSigner struct {
	client   *rpc.Client
	endpoint string
	status   string
	cacheMu  sync.RWMutex
	cache    []accounts.Account
}

func NewExternalSigner(endpoint string) (*ExternalSigner, error) {
	client, err := rpc.Dial(endpoint)
	if err != nil {
		return nil, err
	}
	extsigner := &ExternalSigner{
		client:   client,
		endpoint: endpoint,
	}
	// Check if reachable
	// 检查是否可达
	version, err := extsigner.pingVersion()
	if err != nil {
		return nil, err
	}
	extsigner.status = fmt.Sprintf("ok [version=%v]", version)
	return extsigner, nil
}

func (api *ExternalSigner) URL() accounts.URL {
	return accounts.URL{
		Scheme: "extapi",
		Path:   api.endpoint,
	}
}

func (api *ExternalSigner) Status() (string, error) {
	return api.status, nil
}

func (api *ExternalSigner) Open(passphrase string) error {
	return errors.New("operation not supported on external signers")
}

func (api *ExternalSigner) Close() error {
	return errors.New("operation not supported on external signers")
}

func (api *ExternalSigner) Accounts() []accounts.Account {
	var accnts []accounts.Account
	res, err := api.listAccounts()
	if err != nil {
		log.Error("account listing failed", "error", err)
		return accnts
	}
	for _, addr := range res {
		accnts = append(accnts, accounts.Account{
			URL: accounts.URL{
				Scheme: "extapi",
				Path:   api.endpoint,
			},
			Address: addr,
		})
	}
	api.cacheMu.Lock()
	api.cache = accnts
	api.cacheMu.Unlock()
	return accnts
}

func (api *ExternalSigner) Contains(account accounts.Account) bool {
	api.cacheMu.RLock()
	defer api.cacheMu.RUnlock()
	if api.cache == nil {
		// If we haven't already fetched the accounts, it's time to do so now
		// 如果我们还没有获取帐户，现在就该这样做了
		api.cacheMu.RUnlock()
		api.Accounts()
		api.cacheMu.RLock()
	}
	for _, a := range api.cache {
		if a.Address == account.Address && (account.URL == (accounts.URL{}) || account.URL == api.URL()) {
			return true
		}
	}
	return false
}

func (api *ExternalSigner) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	return accounts.Account{}, errors.New("operation not supported on external signers")
}

func (api *ExternalSigner) SelfDerive(bases []accounts.DerivationPath, chain ethereum.ChainStateReader) {
	log.Error("operation SelfDerive not supported on external signers")
}

// SignData signs keccak256(data). The mimetype parameter describes the type of data being signed
// SignData 对 keccak256（数据）进行签名。 mimetype 参数描述了被签名的数据类型
func (api *ExternalSigner) SignData(account accounts.Account, mimeType string, data []byte) ([]byte, error) {
	var res hexutil.Bytes
	var signAddress = common.NewMixedcaseAddress(account.Address)
	if err := api.client.Call(&res, "account_signData",
		mimeType,
		&signAddress, // Need to use the pointer here, because of how MarshalJSON is defined // 这里需要使用指针，因为 MarshalJSON 的定义方式
		hexutil.Encode(data)); err != nil {
		return nil, err
	}
	// If V is on 27/28-form, convert to 0/1 for Clique
	// 如果 V 为 27/28 形式，则转换为 Clique 的 0/1
	if mimeType == accounts.MimetypeClique && (res[64] == 27 || res[64] == 28) {
		res[64] -= 27 // Transform V from 27/28 to 0/1 for Clique use // 将 V 从 27/28 转换为 0/1 以供 Clique 使用
	}
	return res, nil
}

func (api *ExternalSigner) SignText(account accounts.Account, text []byte) ([]byte, error) {
	var signature hexutil.Bytes
	var signAddress = common.NewMixedcaseAddress(account.Address)
	if err := api.client.Call(&signature, "account_signData",
		accounts.MimetypeTextPlain,
		&signAddress, // Need to use the pointer here, because of how MarshalJSON is defined // 这里需要使用指针，因为 MarshalJSON 的定义方式
		hexutil.Encode(text)); err != nil {
		return nil, err
	}
	if signature[64] == 27 || signature[64] == 28 {
		// If clef is used as a backend, it may already have transformed the signature to ethereum-type signature.
		// 如果使用 clef 作为后端，它可能已经将签名转换为以太坊类型的签名。
		signature[64] -= 27 // Transform V from Ethereum-legacy to 0/1 // 将 V 从以太坊传统转变为 0/1
	}
	return signature, nil
}

// signTransactionResult represents the signinig result returned by clef.
// signTransactionResult 表示 clef 返回的签名结果。
type signTransactionResult struct {
	Raw hexutil.Bytes      `json:"raw"`
	Tx  *types.Transaction `json:"tx"`
}

// SignTx sends the transaction to the external signer. If chainID is nil, or tx.ChainID is zero, the chain ID will be assigned by the external signer. For non-legacy transactions, the chain ID of the transaction overrides the chainID parameter.
// SignTx 将交易发送给外部签名者。如果 chainID 为零，或者 tx.ChainID 为零，则链 ID 将由外部签名者分配。对于非旧版交易，交易的链 ID 会覆盖 chainID 参数。
func (api *ExternalSigner) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	data := hexutil.Bytes(tx.Data())
	var to *common.MixedcaseAddress
	if tx.To() != nil {
		t := common.NewMixedcaseAddress(*tx.To())
		to = &t
	}
	args := &apitypes.SendTxArgs{
		Input: &data,
		Nonce: hexutil.Uint64(tx.Nonce()),
		Value: hexutil.Big(*tx.Value()),
		Gas:   hexutil.Uint64(tx.Gas()),
		To:    to,
		From:  common.NewMixedcaseAddress(account.Address),
	}
	switch tx.Type() {
	case types.LegacyTxType, types.AccessListTxType:
		args.GasPrice = (*hexutil.Big)(tx.GasPrice())
	case types.DynamicFeeTxType, types.BlobTxType:
		args.MaxFeePerGas = (*hexutil.Big)(tx.GasFeeCap())
		args.MaxPriorityFeePerGas = (*hexutil.Big)(tx.GasTipCap())
	default:
		return nil, fmt.Errorf("unsupported tx type %d", tx.Type())
	}
	// We should request the default chain id that we're operating with (the chain we're executing on)
	// 我们应该请求我们正在操作的默认链 ID（我们正在执行的链）
	if chainID != nil && chainID.Sign() != 0 {
		args.ChainID = (*hexutil.Big)(chainID)
	}
	if tx.Type() != types.LegacyTxType {
		// However, if the user asked for a particular chain id, then we should use that instead.
		// 但是，如果用户要求特定的链 ID，那么我们应该使用它。
		if tx.ChainId().Sign() != 0 {
			args.ChainID = (*hexutil.Big)(tx.ChainId())
		}
		accessList := tx.AccessList()
		args.AccessList = &accessList
	}
	if tx.Type() == types.BlobTxType {
		args.BlobHashes = tx.BlobHashes()
		sidecar := tx.BlobTxSidecar()
		if sidecar == nil {
			return nil, errors.New("blobs must be present for signing")
		}
		args.Blobs = sidecar.Blobs
		args.Commitments = sidecar.Commitments
		args.Proofs = sidecar.Proofs
	}

	var res signTransactionResult
	if err := api.client.Call(&res, "account_signTransaction", args); err != nil {
		return nil, err
	}
	return res.Tx, nil
}

func (api *ExternalSigner) SignTextWithPassphrase(account accounts.Account, passphrase string, text []byte) ([]byte, error) {
	return []byte{}, errors.New("password-operations not supported on external signers")
}

func (api *ExternalSigner) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return nil, errors.New("password-operations not supported on external signers")
}
func (api *ExternalSigner) SignDataWithPassphrase(account accounts.Account, passphrase, mimeType string, data []byte) ([]byte, error) {
	return nil, errors.New("password-operations not supported on external signers")
}

func (api *ExternalSigner) listAccounts() ([]common.Address, error) {
	var res []common.Address
	if err := api.client.Call(&res, "account_list"); err != nil {
		return nil, err
	}
	return res, nil
}

func (api *ExternalSigner) pingVersion() (string, error) {
	var v string
	if err := api.client.Call(&v, "account_version"); err != nil {
		return "", err
	}
	return v, nil
}


