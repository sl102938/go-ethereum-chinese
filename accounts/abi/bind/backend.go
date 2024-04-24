// Copyright 2015 The go-ethereum Authors
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
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

var (
	// ErrNoCode is returned by call and transact operations for which the requested recipient contract to operate on does not exist in the state db or does not have any code associated with it (i.e. self-destructed).
	// ErrNoCode 由调用和交易操作返回，其中所请求的要操作的接收者合约在状态数据库中不存在或没有任何与其关联的代码（即自毁）。
	ErrNoCode = errors.New("no contract code at given address")

	// ErrNoPendingState is raised when attempting to perform a pending state action on a backend that doesn't implement PendingContractCaller.
	// 当尝试在未实现 PendingContractCaller 的后端上执行挂起状态操作时，会引发 ErrNoPendingState。
	ErrNoPendingState = errors.New("backend does not support pending state")

	// ErrNoBlockHashState is raised when attempting to perform a block hash action on a backend that doesn't implement BlockHashContractCaller.
	// 当尝试在未实现 BlockHashContractCaller 的后端执行块哈希操作时，会引发 ErrNoBlockHashState。
	ErrNoBlockHashState = errors.New("backend does not support block hash state")

	// ErrNoCodeAfterDeploy is returned by WaitDeployed if contract creation leaves an empty contract behind.
	// 如果合约创建留下了一个空合约，则 WaitDeployed 将返回 ErrNoCodeAfterDeploy。
	ErrNoCodeAfterDeploy = errors.New("no contract code after deployment")
)

// ContractCaller defines the methods needed to allow operating with a contract on a read only basis.
// ContractCaller 定义了允许在只读基础上操作合约所需的方法。
type ContractCaller interface {
	// CodeAt returns the code of the given account. This is needed to differentiate between contract internal errors and the local chain being out of sync.
	// CodeAt 返回给定帐户的代码。这是为了区分合约内部错误​​和本地链不同步。
	CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error)

	// CallContract executes an Ethereum contract call with the specified data as the input.
	// CallContract 使用指定数据作为输入执行以太坊合约调用。
	CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

// PendingContractCaller defines methods to perform contract calls on the pending state. Call will try to discover this interface when access to the pending state is requested. If the backend does not support the pending state, Call returns ErrNoPendingState.
// PendingContractCaller 定义了对挂起状态执行合约调用的方法。当请求访问挂起状态时，调用将尝试发现此接口。如果后端不支持挂起状态，则 Call 返回 ErrNoPendingState。
type PendingContractCaller interface {
	// PendingCodeAt returns the code of the given account in the pending state.
	// PendingCodeAt 返回处于待处理状态的给定帐户的代码。
	PendingCodeAt(ctx context.Context, contract common.Address) ([]byte, error)

	// PendingCallContract executes an Ethereum contract call against the pending state.
	// PendingCallContract 针对待处理状态执行以太坊合约调用。
	PendingCallContract(ctx context.Context, call ethereum.CallMsg) ([]byte, error)
}

// BlockHashContractCaller defines methods to perform contract calls on a specific block hash. Call will try to discover this interface when access to a block by hash is requested. If the backend does not support the block hash state, Call returns ErrNoBlockHashState.
// BlockHashContractCaller 定义了对特定块哈希执行合约调用的方法。当请求通过哈希访问块时，调用将尝试发现此接口。如果后端不支持区块哈希状态，则Call返回ErrNoBlockHashState。
type BlockHashContractCaller interface {
	// CodeAtHash returns the code of the given account in the state at the specified block hash.
	// CodeAtHash 返回指定块哈希状态下给定帐户的代码。
	CodeAtHash(ctx context.Context, contract common.Address, blockHash common.Hash) ([]byte, error)

	// CallContractAtHash executes an Ethereum contract call against the state at the specified block hash.
	// CallContractAtHash 针对指定区块哈希的状态执行以太坊合约调用。
	CallContractAtHash(ctx context.Context, call ethereum.CallMsg, blockHash common.Hash) ([]byte, error)
}

// ContractTransactor defines the methods needed to allow operating with a contract on a write only basis. Besides the transacting method, the remainder are helpers used when the user does not provide some needed values, but rather leaves it up to the transactor to decide.
// ContractTransactor 定义了允许在只写的基础上操作合约所需的方法。除了交易方法之外，其余的都是当用户不提供某些需要的值时使用的帮助程序，而是将其留给交易者来决定。
type ContractTransactor interface {
	ethereum.GasEstimator
	ethereum.GasPricer
	ethereum.GasPricer1559
	ethereum.TransactionSender

	// HeaderByNumber returns a block header from the current canonical chain. If number is nil, the latest known header is returned.
	// HeaderByNumber 返回当前规范链中的块头。如果 number 为零，则返回最新的已知标头。
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)

	// PendingCodeAt returns the code of the given account in the pending state.
	// PendingCodeAt 返回处于待处理状态的给定帐户的代码。
	PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error)

	// PendingNonceAt retrieves the current pending nonce associated with an account.
	// PendingNonceAt 检索与帐户关联的当前待处理随机数。
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
}

// DeployBackend wraps the operations needed by WaitMined and WaitDeployed.
// DeployBackend 包装了 WaitMined 和 WaitDeployed 所需的操作。
type DeployBackend interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
}

// ContractFilterer defines the methods needed to access log events using one-off queries or continuous event subscriptions.
// ContractFilterer 定义了使用一次性查询或连续事件订阅访问日志事件所需的方法。
type ContractFilterer interface {
	ethereum.LogFilterer
}

// ContractBackend defines the methods needed to work with contracts on a read-write basis.
// ContractBackend 定义了以读写方式处理合约所需的方法。
type ContractBackend interface {
	ContractCaller
	ContractTransactor
	ContractFilterer
}


