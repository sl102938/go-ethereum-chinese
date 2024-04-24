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
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
)

const basefeeWiggleMultiplier = 2

var (
	errNoEventSignature       = errors.New("no event signature")
	errEventSignatureMismatch = errors.New("event signature mismatch")
)

// SignerFn is a signer function callback when a contract requires a method to sign the transaction before submission.
// SignerFn 是当合约需要在提交之前签署交易的方法时的签名者函数回调。
type SignerFn func(common.Address, *types.Transaction) (*types.Transaction, error)

// CallOpts is the collection of options to fine tune a contract call request.
// CallOpts 是用于微调合约调用请求的选项集合。
type CallOpts struct {
	Pending     bool            // Whether to operate on the pending state or the last known one // 是否对待处理状态或最后已知状态进行操作
	From        common.Address  // Optional the sender address, otherwise the first account is used // 可选的发件人地址，否则使用第一个帐户
	BlockNumber *big.Int        // Optional the block number on which the call should be performed // 可选的应执行呼叫的块号
	BlockHash   common.Hash     // Optional the block hash on which the call should be performed // 可选的应执行调用的块哈希
	Context     context.Context // Network context to support cancellation and timeouts (nil = no timeout) // 支持取消和超时的网络上下文（nil = 无超时）
}

// TransactOpts is the collection of authorization data required to create a valid Ethereum transaction.
// TransactOpts 是创建有效的以太坊交易所需的授权数据的集合。
type TransactOpts struct {
	From   common.Address // Ethereum account to send the transaction from // 用于发送交易的以太坊账户
	Nonce  *big.Int       // Nonce to use for the transaction execution (nil = use pending state) // 用于事务执行的随机数（nil = 使用挂起状态）
	Signer SignerFn       // Method to use for signing the transaction (mandatory) // 用于签署交易的方法（必填）

	Value     *big.Int // Funds to transfer along the transaction (nil = 0 = no funds) // 交易中转移的资金（nil = 0 = 无资金）
	GasPrice  *big.Int // Gas price to use for the transaction execution (nil = gas price oracle) // 用于交易执行的 Gas 价格（nil = Gas 价格预言机）
	GasFeeCap *big.Int // Gas fee cap to use for the 1559 transaction execution (nil = gas price oracle) // 用于执行 1559 笔交易的 Gas 费上限（nil = Gas 价格预言机）
	GasTipCap *big.Int // Gas priority fee cap to use for the 1559 transaction execution (nil = gas price oracle) // 用于执行 1559 笔交易的 Gas 优先费上限（nil = Gas 价格预言机）
	GasLimit  uint64   // Gas limit to set for the transaction execution (0 = estimate) // 为交易执行设置的 Gas 限制（0 = 估计）

	Context context.Context // Network context to support cancellation and timeouts (nil = no timeout) // 支持取消和超时的网络上下文（nil = 无超时）

	NoSend bool // Do all transact steps but do not send the transaction // 执行所有交易步骤但不发送交易
}

// FilterOpts is the collection of options to fine tune filtering for events within a bound contract.
// FilterOpts 是用于微调绑定合约内事件过滤的选项集合。
type FilterOpts struct {
	Start uint64  // Start of the queried range // 查询范围的开始
	End   *uint64 // End of the range (nil = latest) // 范围结束（nil = 最新）

	Context context.Context // Network context to support cancellation and timeouts (nil = no timeout) // 支持取消和超时的网络上下文（nil = 无超时）
}

// WatchOpts is the collection of options to fine tune subscribing for events within a bound contract.
// WatchOpts 是用于微调绑定合约内事件订阅的选项集合。
type WatchOpts struct {
	Start   *uint64         // Start of the queried range (nil = latest) // 查询范围的开始（nil = 最新）
	Context context.Context // Network context to support cancellation and timeouts (nil = no timeout) // 支持取消和超时的网络上下文（nil = 无超时）
}

// MetaData collects all metadata for a bound contract.
// 元数据收集绑定合约的所有元数据。
type MetaData struct {
	mu   sync.Mutex
	Sigs map[string]string
	Bin  string
	ABI  string
	ab   *abi.ABI
}

func (m *MetaData) GetAbi() (*abi.ABI, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ab != nil {
		return m.ab, nil
	}
	if parsed, err := abi.JSON(strings.NewReader(m.ABI)); err != nil {
		return nil, err
	} else {
		m.ab = &parsed
	}
	return m.ab, nil
}

// BoundContract is the base wrapper object that reflects a contract on the Ethereum network. It contains a collection of methods that are used by the higher level contract bindings to operate.
// BoundContract 是反映以太坊网络上合约的基本包装对象。它包含高层合约绑定用来操作的方法集合。
type BoundContract struct {
	address    common.Address     // Deployment address of the contract on the Ethereum blockchain // 合约在以太坊区块链上的部署地址
	abi        abi.ABI            // Reflect based ABI to access the correct Ethereum methods // 基于反射的 ABI 来访问正确的以太坊方法
	caller     ContractCaller     // Read interface to interact with the blockchain // 读取接口与区块链交互
	transactor ContractTransactor // Write interface to interact with the blockchain // 编写与区块链交互的接口
	filterer   ContractFilterer   // Event filtering to interact with the blockchain // 事件过滤与区块链交互
}

// NewBoundContract creates a low level contract interface through which calls and transactions may be made through.
// NewBoundContract 创建一个低级合约接口，通过该接口可以进行调用和交易。
func NewBoundContract(address common.Address, abi abi.ABI, caller ContractCaller, transactor ContractTransactor, filterer ContractFilterer) *BoundContract {
	return &BoundContract{
		address:    address,
		abi:        abi,
		caller:     caller,
		transactor: transactor,
		filterer:   filterer,
	}
}

// DeployContract deploys a contract onto the Ethereum blockchain and binds the deployment address with a Go wrapper.
// DeployContract 将合约部署到以太坊区块链上，并将部署地址与 Go 包装器绑定。
func DeployContract(opts *TransactOpts, abi abi.ABI, bytecode []byte, backend ContractBackend, params ...interface{}) (common.Address, *types.Transaction, *BoundContract, error) {
	// Otherwise try to deploy the contract
	// 否则尝试部署合约
	c := NewBoundContract(common.Address{}, abi, backend, backend, backend)

	input, err := c.abi.Pack("", params...)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	tx, err := c.transact(opts, nil, append(bytecode, input...))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	c.address = crypto.CreateAddress(opts.From, tx.Nonce())
	return c.address, tx, c, nil
}

// Call invokes the (constant) contract method with params as input values and sets the output to result. The result type might be a single field for simple returns, a slice of interfaces for anonymous returns and a struct for named returns.
// Call 使用 params 作为输入值调用（常量）合约方法，并将输出设置为 result。结果类型可能是用于简单返回的单个字段、用于匿名返回的接口切片以及用于命名返回的结构。
func (c *BoundContract) Call(opts *CallOpts, results *[]interface{}, method string, params ...interface{}) error {
	// Don't crash on a lazy user
	// 不要让懒惰的用户崩溃
	if opts == nil {
		opts = new(CallOpts)
	}
	if results == nil {
		results = new([]interface{})
	}
	// Pack the input, call and unpack the results
	// 打包输入，调用并解包结果
	input, err := c.abi.Pack(method, params...)
	if err != nil {
		return err
	}
	var (
		msg    = ethereum.CallMsg{From: opts.From, To: &c.address, Data: input}
		ctx    = ensureContext(opts.Context)
		code   []byte
		output []byte
	)
	if opts.Pending {
		pb, ok := c.caller.(PendingContractCaller)
		if !ok {
			return ErrNoPendingState
		}
		output, err = pb.PendingCallContract(ctx, msg)
		if err != nil {
			return err
		}
		if len(output) == 0 {
			// Make sure we have a contract to operate on, and bail out otherwise.
			// 确保我们有一份可以运作的合同，否则就退出。
			if code, err = pb.PendingCodeAt(ctx, c.address); err != nil {
				return err
			} else if len(code) == 0 {
				return ErrNoCode
			}
		}
	} else if opts.BlockHash != (common.Hash{}) {
		bh, ok := c.caller.(BlockHashContractCaller)
		if !ok {
			return ErrNoBlockHashState
		}
		output, err = bh.CallContractAtHash(ctx, msg, opts.BlockHash)
		if err != nil {
			return err
		}
		if len(output) == 0 {
			// Make sure we have a contract to operate on, and bail out otherwise.
			// 确保我们有一份可以运作的合同，否则就退出。
			if code, err = bh.CodeAtHash(ctx, c.address, opts.BlockHash); err != nil {
				return err
			} else if len(code) == 0 {
				return ErrNoCode
			}
		}
	} else {
		output, err = c.caller.CallContract(ctx, msg, opts.BlockNumber)
		if err != nil {
			return err
		}
		if len(output) == 0 {
			// Make sure we have a contract to operate on, and bail out otherwise.
			// 确保我们有一份可以运作的合同，否则就退出。
			if code, err = c.caller.CodeAt(ctx, c.address, opts.BlockNumber); err != nil {
				return err
			} else if len(code) == 0 {
				return ErrNoCode
			}
		}
	}

	if len(*results) == 0 {
		res, err := c.abi.Unpack(method, output)
		*results = res
		return err
	}
	res := *results
	return c.abi.UnpackIntoInterface(res[0], method, output)
}

// Transact invokes the (paid) contract method with params as input values.
// Transact 使用 params 作为输入值调用（付费）合约方法。
func (c *BoundContract) Transact(opts *TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	// Otherwise pack up the parameters and invoke the contract
	// 否则打包参数并调用合约
	input, err := c.abi.Pack(method, params...)
	if err != nil {
		return nil, err
	}
	// todo(rjl493456442) check whether the method is payable or not, reject invalid transaction at the first place
	// todo(rjl493456442) 检查该方法是否可支付，首先拒绝无效交易
	return c.transact(opts, &c.address, input)
}

// RawTransact initiates a transaction with the given raw calldata as the input. It's usually used to initiate transactions for invoking **Fallback** function.
// RawTransact 使用给定的原始调用数据作为输入启动交易。通常用于发起交易以调用 **Fallback** 功能。
func (c *BoundContract) RawTransact(opts *TransactOpts, calldata []byte) (*types.Transaction, error) {
	// todo(rjl493456442) check whether the method is payable or not, reject invalid transaction at the first place
	// todo(rjl493456442) 检查该方法是否可支付，首先拒绝无效交易
	return c.transact(opts, &c.address, calldata)
}

// Transfer initiates a plain transaction to move funds to the contract, calling its default method if one is available.
// Transfer 启动一项普通交易，将资金转移到合约中，并调用其默认方法（如果可用）。
func (c *BoundContract) Transfer(opts *TransactOpts) (*types.Transaction, error) {
	// todo(rjl493456442) check the payable fallback or receive is defined or not, reject invalid transaction at the first place
	// todo(rjl493456442) 检查应付回退或接收是否已定义，首先拒绝无效交易
	return c.transact(opts, &c.address, nil)
}

func (c *BoundContract) createDynamicTx(opts *TransactOpts, contract *common.Address, input []byte, head *types.Header) (*types.Transaction, error) {
	// Normalize value
	// 标准化值
	value := opts.Value
	if value == nil {
		value = new(big.Int)
	}
	// Estimate TipCap
	// 估计小费上限
	gasTipCap := opts.GasTipCap
	if gasTipCap == nil {
		tip, err := c.transactor.SuggestGasTipCap(ensureContext(opts.Context))
		if err != nil {
			return nil, err
		}
		gasTipCap = tip
	}
	// Estimate FeeCap
	// 预估费用上限
	gasFeeCap := opts.GasFeeCap
	if gasFeeCap == nil {
		gasFeeCap = new(big.Int).Add(
			gasTipCap,
			new(big.Int).Mul(head.BaseFee, big.NewInt(basefeeWiggleMultiplier)),
		)
	}
	if gasFeeCap.Cmp(gasTipCap) < 0 {
		return nil, fmt.Errorf("maxFeePerGas (%v) < maxPriorityFeePerGas (%v)", gasFeeCap, gasTipCap)
	}
	// Estimate GasLimit
	// 估计 GasLimit
	gasLimit := opts.GasLimit
	if opts.GasLimit == 0 {
		var err error
		gasLimit, err = c.estimateGasLimit(opts, contract, input, nil, gasTipCap, gasFeeCap, value)
		if err != nil {
			return nil, err
		}
	}
	// create the transaction
	// 创建交易
	nonce, err := c.getNonce(opts)
	if err != nil {
		return nil, err
	}
	baseTx := &types.DynamicFeeTx{
		To:        contract,
		Nonce:     nonce,
		GasFeeCap: gasFeeCap,
		GasTipCap: gasTipCap,
		Gas:       gasLimit,
		Value:     value,
		Data:      input,
	}
	return types.NewTx(baseTx), nil
}

func (c *BoundContract) createLegacyTx(opts *TransactOpts, contract *common.Address, input []byte) (*types.Transaction, error) {
	if opts.GasFeeCap != nil || opts.GasTipCap != nil {
		return nil, errors.New("maxFeePerGas or maxPriorityFeePerGas specified but london is not active yet")
	}
	// Normalize value
	// 标准化值
	value := opts.Value
	if value == nil {
		value = new(big.Int)
	}
	// Estimate GasPrice
	// 预估 GasPrice
	gasPrice := opts.GasPrice
	if gasPrice == nil {
		price, err := c.transactor.SuggestGasPrice(ensureContext(opts.Context))
		if err != nil {
			return nil, err
		}
		gasPrice = price
	}
	// Estimate GasLimit
	// 估计 GasLimit
	gasLimit := opts.GasLimit
	if opts.GasLimit == 0 {
		var err error
		gasLimit, err = c.estimateGasLimit(opts, contract, input, gasPrice, nil, nil, value)
		if err != nil {
			return nil, err
		}
	}
	// create the transaction
	// 创建交易
	nonce, err := c.getNonce(opts)
	if err != nil {
		return nil, err
	}
	baseTx := &types.LegacyTx{
		To:       contract,
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gasLimit,
		Value:    value,
		Data:     input,
	}
	return types.NewTx(baseTx), nil
}

func (c *BoundContract) estimateGasLimit(opts *TransactOpts, contract *common.Address, input []byte, gasPrice, gasTipCap, gasFeeCap, value *big.Int) (uint64, error) {
	if contract != nil {
		// Gas estimation cannot succeed without code for method invocations.
		// 如果没有方法调用代码，气体估计就无法成功。
		if code, err := c.transactor.PendingCodeAt(ensureContext(opts.Context), c.address); err != nil {
			return 0, err
		} else if len(code) == 0 {
			return 0, ErrNoCode
		}
	}
	msg := ethereum.CallMsg{
		From:      opts.From,
		To:        contract,
		GasPrice:  gasPrice,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Value:     value,
		Data:      input,
	}
	return c.transactor.EstimateGas(ensureContext(opts.Context), msg)
}

func (c *BoundContract) getNonce(opts *TransactOpts) (uint64, error) {
	if opts.Nonce == nil {
		return c.transactor.PendingNonceAt(ensureContext(opts.Context), opts.From)
	} else {
		return opts.Nonce.Uint64(), nil
	}
}

// transact executes an actual transaction invocation, first deriving any missing authorization fields, and then scheduling the transaction for execution.
// transact 执行实际的事务调用，首先派生任何缺失的授权字段，然后安排事务执行。
func (c *BoundContract) transact(opts *TransactOpts, contract *common.Address, input []byte) (*types.Transaction, error) {
	if opts.GasPrice != nil && (opts.GasFeeCap != nil || opts.GasTipCap != nil) {
		return nil, errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")
	}
	// Create the transaction
	// 创建交易
	var (
		rawTx *types.Transaction
		err   error
	)
	if opts.GasPrice != nil {
		rawTx, err = c.createLegacyTx(opts, contract, input)
	} else if opts.GasFeeCap != nil && opts.GasTipCap != nil {
		rawTx, err = c.createDynamicTx(opts, contract, input, nil)
	} else {
		// Only query for basefee if gasPrice not specified
		// 如果未指定gasPrice，则仅查询basefee
		if head, errHead := c.transactor.HeaderByNumber(ensureContext(opts.Context), nil); errHead != nil {
			return nil, errHead
		} else if head.BaseFee != nil {
			rawTx, err = c.createDynamicTx(opts, contract, input, head)
		} else {
			// Chain is not London ready -> use legacy transaction
			// 伦敦链尚未准备好 -> 使用遗留交易
			rawTx, err = c.createLegacyTx(opts, contract, input)
		}
	}
	if err != nil {
		return nil, err
	}
	// Sign the transaction and schedule it for execution
	// 签署交易并安排执行
	if opts.Signer == nil {
		return nil, errors.New("no signer to authorize the transaction with")
	}
	signedTx, err := opts.Signer(opts.From, rawTx)
	if err != nil {
		return nil, err
	}
	if opts.NoSend {
		return signedTx, nil
	}
	if err := c.transactor.SendTransaction(ensureContext(opts.Context), signedTx); err != nil {
		return nil, err
	}
	return signedTx, nil
}

// FilterLogs filters contract logs for past blocks, returning the necessary channels to construct a strongly typed bound iterator on top of them.
// FilterLogs 过滤过去区块的合约日志，返回必要的通道以在其之上构造强类型绑定迭代器。
func (c *BoundContract) FilterLogs(opts *FilterOpts, name string, query ...[]interface{}) (chan types.Log, event.Subscription, error) {
	// Don't crash on a lazy user
	// 不要让懒惰的用户崩溃
	if opts == nil {
		opts = new(FilterOpts)
	}
	// Append the event selector to the query parameters and construct the topic set
	// 将事件选择器附加到查询参数并构造主题集
	query = append([][]interface{}{{c.abi.Events[name].ID}}, query...)

	topics, err := abi.MakeTopics(query...)
	if err != nil {
		return nil, nil, err
	}
	// Start the background filtering
	// 启动背景过滤
	logs := make(chan types.Log, 128)

	config := ethereum.FilterQuery{
		Addresses: []common.Address{c.address},
		Topics:    topics,
		FromBlock: new(big.Int).SetUint64(opts.Start),
	}
	if opts.End != nil {
		config.ToBlock = new(big.Int).SetUint64(*opts.End)
	}
	/* TODO(karalabe): Replace the rest of the method below with this when supported
	sub, err := c.filterer.SubscribeFilterLogs(ensureContext(opts.Context), config, logs)
	*/
	buff, err := c.filterer.FilterLogs(ensureContext(opts.Context), config)
	if err != nil {
		return nil, nil, err
	}
	sub := event.NewSubscription(func(quit <-chan struct{}) error {
		for _, log := range buff {
			select {
			case logs <- log:
			case <-quit:
				return nil
			}
		}
		return nil
	})

	return logs, sub, nil
}

// WatchLogs filters subscribes to contract logs for future blocks, returning a subscription object that can be used to tear down the watcher.
// WatchLogs 过滤器订阅未来区块的合约日志，返回可用于拆除观察者的订阅对象。
func (c *BoundContract) WatchLogs(opts *WatchOpts, name string, query ...[]interface{}) (chan types.Log, event.Subscription, error) {
	// Don't crash on a lazy user
	// 不要让懒惰的用户崩溃
	if opts == nil {
		opts = new(WatchOpts)
	}
	// Append the event selector to the query parameters and construct the topic set
	// 将事件选择器附加到查询参数并构造主题集
	query = append([][]interface{}{{c.abi.Events[name].ID}}, query...)

	topics, err := abi.MakeTopics(query...)
	if err != nil {
		return nil, nil, err
	}
	// Start the background filtering
	// 启动背景过滤
	logs := make(chan types.Log, 128)

	config := ethereum.FilterQuery{
		Addresses: []common.Address{c.address},
		Topics:    topics,
	}
	if opts.Start != nil {
		config.FromBlock = new(big.Int).SetUint64(*opts.Start)
	}
	sub, err := c.filterer.SubscribeFilterLogs(ensureContext(opts.Context), config, logs)
	if err != nil {
		return nil, nil, err
	}
	return logs, sub, nil
}

// UnpackLog unpacks a retrieved log into the provided output structure.
// UnpackLog 将检索到的日志解压到提供的输出结构中。
func (c *BoundContract) UnpackLog(out interface{}, event string, log types.Log) error {
	// Anonymous events are not supported.
	// 不支持匿名事件。
	if len(log.Topics) == 0 {
		return errNoEventSignature
	}
	if log.Topics[0] != c.abi.Events[event].ID {
		return errEventSignatureMismatch
	}
	if len(log.Data) > 0 {
		if err := c.abi.UnpackIntoInterface(out, event, log.Data); err != nil {
			return err
		}
	}
	var indexed abi.Arguments
	for _, arg := range c.abi.Events[event].Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}
	return abi.ParseTopics(out, indexed, log.Topics[1:])
}

// UnpackLogIntoMap unpacks a retrieved log into the provided map.
// UnpackLogIntoMap 将检索到的日志解压到提供的映射中。
func (c *BoundContract) UnpackLogIntoMap(out map[string]interface{}, event string, log types.Log) error {
	// Anonymous events are not supported.
	// 不支持匿名事件。
	if len(log.Topics) == 0 {
		return errNoEventSignature
	}
	if log.Topics[0] != c.abi.Events[event].ID {
		return errEventSignatureMismatch
	}
	if len(log.Data) > 0 {
		if err := c.abi.UnpackIntoMap(out, event, log.Data); err != nil {
			return err
		}
	}
	var indexed abi.Arguments
	for _, arg := range c.abi.Events[event].Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}
	return abi.ParseTopicsIntoMap(out, indexed, log.Topics[1:])
}

// ensureContext is a helper method to ensure a context is not nil, even if the user specified it as such.
// EnsureContext 是一个帮助方法，用于确保上下文不为零，即使用户如此指定。
func ensureContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}


