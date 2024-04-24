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

// This file contains the implementation for interacting with the Ledger hardware
// wallets. The wire protocol spec can be found in the Ledger Blue GitHub repo:
// https://github.com/LedgerHQ/app-ethereum/blob/develop/doc/ethapp.adoc

package usbwallet

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// ledgerOpcode is an enumeration encoding the supported Ledger opcodes.
// ledgerOpcode 是对支持的 Ledger 操作码进行编码的枚举。
type ledgerOpcode byte

// ledgerParam1 is an enumeration encoding the supported Ledger parameters for specific opcodes. The same parameter values may be reused between opcodes.
// ledgerParam1 是一个枚举，对特定操作码支持的 Ledger 参数进行编码。相同的参数值可以在操作码之间重复使用。
type ledgerParam1 byte

// ledgerParam2 is an enumeration encoding the supported Ledger parameters for specific opcodes. The same parameter values may be reused between opcodes.
// ledgerParam2 是一个枚举，对特定操作码支持的 Ledger 参数进行编码。相同的参数值可以在操作码之间重复使用。
type ledgerParam2 byte

const (
	ledgerOpRetrieveAddress  ledgerOpcode = 0x02 // Returns the public key and Ethereum address for a given BIP 32 path // 返回给定 BIP 32 路径的公钥和以太坊地址
	ledgerOpSignTransaction  ledgerOpcode = 0x04 // Signs an Ethereum transaction after having the user validate the parameters // 让用户验证参数后签署以太坊交易
	ledgerOpGetConfiguration ledgerOpcode = 0x06 // Returns specific wallet application configuration // 返回特定钱包应用程序配置
	ledgerOpSignTypedMessage ledgerOpcode = 0x0c // Signs an Ethereum message following the EIP 712 specification // 遵循 EIP 712 规范签署以太坊消息

	ledgerP1DirectlyFetchAddress    ledgerParam1 = 0x00 // Return address directly from the wallet // 直接从钱包返回地址
	ledgerP1InitTypedMessageData    ledgerParam1 = 0x00 // First chunk of Typed Message data // 第一个类型化消息数据块
	ledgerP1InitTransactionData     ledgerParam1 = 0x00 // First transaction data block for signing // 第一个用于签名的交易数据块
	ledgerP1ContTransactionData     ledgerParam1 = 0x80 // Subsequent transaction data block for signing // 后续交易数据块进行签名
	ledgerP2DiscardAddressChainCode ledgerParam2 = 0x00 // Do not return the chain code along with the address // 不要将链码与地址一起返回

	ledgerEip155Size int = 3 // Size of the EIP-155 chain_id,r,s in unsigned transactions // 未签名交易中 EIP-155 chain_id,r,s 的大小
)

// errLedgerReplyInvalidHeader is the error message returned by a Ledger data exchange if the device replies with a mismatching header. This usually means the device is in browser mode.
// errLedgerReplyInvalidHeader 是当设备回复不匹配的标头时 Ledger 数据交换返回的错误消息。这通常意味着设备处于浏览器模式。
var errLedgerReplyInvalidHeader = errors.New("ledger: invalid reply header")

// errLedgerInvalidVersionReply is the error message returned by a Ledger version retrieval when a response does arrive, but it does not contain the expected data.
// errLedgerInvalidVersionReply 是当响应到达但不包含预期数据时 Ledger 版本检索返回的错误消息。
var errLedgerInvalidVersionReply = errors.New("ledger: invalid version reply")

// ledgerDriver implements the communication with a Ledger hardware wallet.
// ledgerDriver 实现与 Ledger 硬件钱包的通信。
type ledgerDriver struct {
	device  io.ReadWriter // USB device connection to communicate through // USB设备连接通过
	version [3]byte       // Current version of the Ledger firmware (zero if app is offline) // Ledger 固件的当前版本（如果应用程序离线则为零）
	browser bool          // Flag whether the Ledger is in browser mode (reply channel mismatch) // 标记 Ledger 是否处于浏览器模式（回复通道不匹配）
	failure error         // Any failure that would make the device unusable // 任何导致设备无法使用的故障
	log     log.Logger    // Contextual logger to tag the ledger with its id // 上下文记录器用其 id 标记分类帐
}

// newLedgerDriver creates a new instance of a Ledger USB protocol driver.
// newLedgerDriver 创建 Ledger USB 协议驱动程序的新实例。
func newLedgerDriver(logger log.Logger) driver {
	return &ledgerDriver{
		log: logger,
	}
}

// Status implements usbwallet.driver, returning various states the Ledger can currently be in.
// Status 实现 usbwallet.driver，返回 Ledger 当前可能处于的各种状态。
func (w *ledgerDriver) Status() (string, error) {
	if w.failure != nil {
		return fmt.Sprintf("Failed: %v", w.failure), w.failure
	}
	if w.browser {
		return "Ethereum app in browser mode", w.failure
	}
	if w.offline() {
		return "Ethereum app offline", w.failure
	}
	return fmt.Sprintf("Ethereum app v%d.%d.%d online", w.version[0], w.version[1], w.version[2]), w.failure
}

// offline returns whether the wallet and the Ethereum app is offline or not.
// 离线返回钱包和以太坊应用程序是否离线。
// The method assumes that the state lock is held!
// 该方法假设状态锁已被持有！
func (w *ledgerDriver) offline() bool {
	return w.version == [3]byte{0, 0, 0}
}

// Open implements usbwallet.driver, attempting to initialize the connection to the Ledger hardware wallet. The Ledger does not require a user passphrase, so that parameter is silently discarded.
// Open 实现 usbwallet.driver，尝试初始化与 Ledger 硬件钱包的连接。 Ledger 不需要用户密码，因此该参数会被默默丢弃。
func (w *ledgerDriver) Open(device io.ReadWriter, passphrase string) error {
	w.device, w.failure = device, nil

	_, err := w.ledgerDerive(accounts.DefaultBaseDerivationPath)
	if err != nil {
		// Ethereum app is not running or in browser mode, nothing more to do, return
		// 以太坊应用程序未运行或处于浏览器模式，无事可做，返回
		if err == errLedgerReplyInvalidHeader {
			w.browser = true
		}
		return nil
	}
	// Try to resolve the Ethereum app's version, will fail prior to v1.0.2
	// 尝试解析以太坊应用程序的版本，在v1.0.2之前会失败
	if w.version, err = w.ledgerVersion(); err != nil {
		w.version = [3]byte{1, 0, 0} // Assume worst case, can't verify if v1.0.0 or v1.0.1 // 假设最坏的情况，无法验证 v1.0.0 还是 v1.0.1
	}
	return nil
}

// Close implements usbwallet.driver, cleaning up and metadata maintained within the Ledger driver.
// Close 实现了 usbwallet.driver，清理并在 Ledger 驱动程序中维护元数据。
func (w *ledgerDriver) Close() error {
	w.browser, w.version = false, [3]byte{}
	return nil
}

// Heartbeat implements usbwallet.driver, performing a sanity check against the Ledger to see if it's still online.
// Heartbeat 实现了 usbwallet.driver，对 Ledger 执行健全性检查以查看它是否仍然在线。
func (w *ledgerDriver) Heartbeat() error {
	if _, err := w.ledgerVersion(); err != nil && err != errLedgerInvalidVersionReply {
		w.failure = err
		return err
	}
	return nil
}

// Derive implements usbwallet.driver, sending a derivation request to the Ledger and returning the Ethereum address located on that derivation path.
// Derive 实现 usbwallet.driver，向 Ledger 发送派生请求并返回位于该派生路径上的以太坊地址。
func (w *ledgerDriver) Derive(path accounts.DerivationPath) (common.Address, error) {
	return w.ledgerDerive(path)
}

// SignTx implements usbwallet.driver, sending the transaction to the Ledger and waiting for the user to confirm or deny the transaction.
// SignTx 实现了 usbwallet.driver，将交易发送到 Ledger 并等待用户确认或拒绝交易。
// Note, if the version of the Ethereum application running on the Ledger wallet is too old to sign EIP-155 transactions, but such is requested nonetheless, an error will be returned opposed to silently signing in Homestead mode.
// 请注意，如果 Ledger 钱包上运行的以太坊应用程序版本太旧，无法签署 EIP-155 交易，但尽管如此，仍会请求这样做，则会返回错误，而不是在 Homestead 模式下静默签名。
func (w *ledgerDriver) SignTx(path accounts.DerivationPath, tx *types.Transaction, chainID *big.Int) (common.Address, *types.Transaction, error) {
	// If the Ethereum app doesn't run, abort
	// 如果以太坊应用程序不运行，则中止
	if w.offline() {
		return common.Address{}, nil, accounts.ErrWalletClosed
	}
	// Ensure the wallet is capable of signing the given transaction
	// 确保钱包能够签署给定的交易
	if chainID != nil && w.version[0] <= 1 && w.version[1] <= 0 && w.version[2] <= 2 {
		//lint:ignore ST1005 brand name displayed on the console
		//lint：忽略控制台上显示的 ST1005 品牌名称
		return common.Address{}, nil, fmt.Errorf("Ledger v%d.%d.%d doesn't support signing this transaction, please update to v1.0.3 at least", w.version[0], w.version[1], w.version[2])
	}
	// All infos gathered and metadata checks out, request signing
	// 收集所有信息并检查元数据，请求签名
	return w.ledgerSign(path, tx, chainID)
}

// SignTypedMessage implements usbwallet.driver, sending the message to the Ledger and waiting for the user to sign or deny the transaction.
// SignTypedMessage 实现 usbwallet.driver，将消息发送到 Ledger 并等待用户签署或拒绝交易。
// Note: this was introduced in the ledger 1.5.0 firmware
// 注意：这是在ledger 1.5.0固件中引入的
func (w *ledgerDriver) SignTypedMessage(path accounts.DerivationPath, domainHash []byte, messageHash []byte) ([]byte, error) {
	// If the Ethereum app doesn't run, abort
	// 如果以太坊应用程序不运行，则中止
	if w.offline() {
		return nil, accounts.ErrWalletClosed
	}
	// Ensure the wallet is capable of signing the given transaction
	// 确保钱包能够签署给定的交易
	if w.version[0] < 1 && w.version[1] < 5 {
		//lint:ignore ST1005 brand name displayed on the console
		//lint：忽略控制台上显示的 ST1005 品牌名称
		return nil, fmt.Errorf("Ledger version >= 1.5.0 required for EIP-712 signing (found version v%d.%d.%d)", w.version[0], w.version[1], w.version[2])
	}
	// All infos gathered and metadata checks out, request signing
	// 收集所有信息并检查元数据，请求签名
	return w.ledgerSignTypedMessage(path, domainHash, messageHash)
}

// ledgerVersion retrieves the current version of the Ethereum wallet app running on the Ledger wallet.
// ledgerVersion 检索 Ledger 钱包上运行的以太坊钱包应用程序的当前版本。
// The version retrieval protocol is defined as follows:
// 版本检索协议定义如下：
//	CLA | INS | P1 | P2 | Lc | Le
//	共轭亚油酸 | INS | P1 | P2 | LC |勒
//	----+-----+----+----+----+---
//	E0 | 06 | 00 | 00 | 00 | 04
//	 E0 | 06  | 00 | 00 | 00 | 04
//	 E0 | 06 | 00 | 00 00 | 00 00 | 00 04
// With no input data, and the output data being:
// 没有输入数据，输出数据为：
//	Description                                        | Length
//	描述 |长度
//	---------------------------------------------------+--------
//	Flags 01: arbitrary data signature enabled by user | 1 byte
//	Flags 01: arbitrary data signature enabled by user | 1 byte
//	标志01：用户启用的任意数据签名| 1字节
//	Application major version                          | 1 byte
//	应用程序主要版本 | 1字节
//	Application minor version                          | 1 byte
//	应用程序次要版本 | 1字节
//	Application patch version                          | 1 byte
//	应用补丁版本 | 1字节
func (w *ledgerDriver) ledgerVersion() ([3]byte, error) {
	// Send the request and wait for the response
	// 发送请求并等待响应
	reply, err := w.ledgerExchange(ledgerOpGetConfiguration, 0, 0, nil)
	if err != nil {
		return [3]byte{}, err
	}
	if len(reply) != 4 {
		return [3]byte{}, errLedgerInvalidVersionReply
	}
	// Cache the version for future reference
	// 缓存版本以供将来参考
	var version [3]byte
	copy(version[:], reply[1:])
	return version, nil
}

// ledgerDerive retrieves the currently active Ethereum address from a Ledger wallet at the specified derivation path.
// ledgerDerive 从指定派生路径的 Ledger 钱包中检索当前活动的以太坊地址。
// The address derivation protocol is defined as follows:
// 地址派生协议定义如下：
//	CLA | INS | P1 | P2 | Lc  | Le
//	共轭亚油酸 | INS | P1 | P2 | LC |勒
//	----+-----+----+----+-----+---
//	E0 | 02 | 00 return address
//	 E0 | 02  | 00 return address
//	 E0 | 02 | 00 返回地址
//	            01 display address and confirm before returning
//	            01 返回前显示地址并确认
//	               | 00: do not return the chain code
//	               | 00：不返回链码
//	               | 01: return the chain code
//	               | 01：返回链码
//	                    | var | 00
//	                    |变量 | 00
// Where the input data is:
// 其中输入数据是：
//	Description                                      | Length
//	描述 |长度
//	-------------------------------------------------+--------
//	Number of BIP 32 derivations to perform (max 10) | 1 byte
//	Number of BIP 32 derivations to perform (max 10) | 1 byte
//	要执行的 BIP 32 派生数量（最多 10）| 1字节
//	First derivation index (big endian)              | 4 bytes
//	一阶导数索引（大端）| 4字节
//	...                                              | 4 bytes
//	... | 4字节
//	Last derivation index (big endian)               | 4 bytes
//	最后派生索引（大端）| 4字节
// And the output data is:
// 输出数据为：
//	Description             | Length
//	描述 |长度
//	------------------------+-------------------
//	Public Key length | 1 byte
//	Public Key length       | 1 byte
//	公钥长度 | 1字节
//	Uncompressed Public Key | arbitrary
//	未压缩的公钥 |随意的
//	Ethereum address length | 1 byte
//	以太坊地址长度 | 1字节
//	Ethereum address        | 40 bytes hex ascii
//	以太坊地址 | 40 字节十六进制 ascii
//	Chain code if requested | 32 bytes
//	如果需要的话链码 | 32字节
func (w *ledgerDriver) ledgerDerive(derivationPath []uint32) (common.Address, error) {
	// Flatten the derivation path into the Ledger request
	// 将派生路径扁平化为 Ledger 请求
	path := make([]byte, 1+4*len(derivationPath))
	path[0] = byte(len(derivationPath))
	for i, component := range derivationPath {
		binary.BigEndian.PutUint32(path[1+4*i:], component)
	}
	// Send the request and wait for the response
	// 发送请求并等待响应
	reply, err := w.ledgerExchange(ledgerOpRetrieveAddress, ledgerP1DirectlyFetchAddress, ledgerP2DiscardAddressChainCode, path)
	if err != nil {
		return common.Address{}, err
	}
	// Discard the public key, we don't need that for now
	// 丢弃公钥，我们暂时不需要它
	if len(reply) < 1 || len(reply) < 1+int(reply[0]) {
		return common.Address{}, errors.New("reply lacks public key entry")
	}
	reply = reply[1+int(reply[0]):]

	// Extract the Ethereum hex address string
	// 提取以太坊十六进制地址字符串
	if len(reply) < 1 || len(reply) < 1+int(reply[0]) {
		return common.Address{}, errors.New("reply lacks address entry")
	}
	hexstr := reply[1 : 1+int(reply[0])]

	// Decode the hex string into an Ethereum address and return
	// 将十六进制字符串解码为以太坊地址并返回
	var address common.Address
	if _, err = hex.Decode(address[:], hexstr); err != nil {
		return common.Address{}, err
	}
	return address, nil
}

// ledgerSign sends the transaction to the Ledger wallet, and waits for the user to confirm or deny the transaction.
// ledgerSign 将交易发送到 Ledger 钱包，并等待用户确认或拒绝交易。
// The transaction signing protocol is defined as follows:
// 交易签名协议定义如下：
//	CLA | INS | P1 | P2 | Lc  | Le
//	共轭亚油酸 | INS | P1 | P2 | LC |勒
//	----+-----+----+----+-----+---
//	E0 | 02 | 00 return address
//	 E0 | 04  | 00: first transaction data block
//	 E0 | 04 | 00：第一个交易数据块
//	            80: subsequent transaction data block
//	            80：后续交易数据块
//	               | 00 | variable | variable
//	               | 00 | 00变量|多变的
// Where the input for the first transaction block (first 255 bytes) is:
// 其中第一个交易块（前 255 个字节）的输入是：
//	Description                                      | Length
//	描述 |长度
//	-------------------------------------------------+----------
//	Number of BIP 32 derivations to perform (max 10) | 1 byte
//	Number of BIP 32 derivations to perform (max 10) | 1 byte
//	要执行的 BIP 32 派生数量（最多 10）| 1字节
//	First derivation index (big endian)              | 4 bytes
//	一阶导数索引（大端）| 4字节
//	...                                              | 4 bytes
//	... | 4字节
//	Last derivation index (big endian)               | 4 bytes
//	最后派生索引（大端）| 4字节
//	RLP transaction chunk                            | arbitrary
//	RLP 交易块 |随意的
// And the input for subsequent transaction blocks (first 255 bytes) are:
// 后续交易块的输入（前 255 个字节）为：
//	Description           | Length
//	描述 |长度
//	----------------------+----------
//	RLP transaction chunk | arbitrary
//	RLP transaction chunk | arbitrary
//	RLP 交易块 |随意的
// And the output data is:
// 输出数据为：
//	Description | Length
//	描述 |长度
//	------------+---------
//	signature V | 1 byte
//	signature V | 1 byte
//	签名V | 1字节
//	signature R | 32 bytes
//	签名R | 32字节
//	signature S | 32 bytes
//	签名 S | 32字节
func (w *ledgerDriver) ledgerSign(derivationPath []uint32, tx *types.Transaction, chainID *big.Int) (common.Address, *types.Transaction, error) {
	// Flatten the derivation path into the Ledger request
	// 将派生路径扁平化为 Ledger 请求
	path := make([]byte, 1+4*len(derivationPath))
	path[0] = byte(len(derivationPath))
	for i, component := range derivationPath {
		binary.BigEndian.PutUint32(path[1+4*i:], component)
	}
	// Create the transaction RLP based on whether legacy or EIP155 signing was requested
	// 根据请求的是传统签名还是 EIP155 签名来创建交易 RLP
	var (
		txrlp []byte
		err   error
	)
	if chainID == nil {
		if txrlp, err = rlp.EncodeToBytes([]interface{}{tx.Nonce(), tx.GasPrice(), tx.Gas(), tx.To(), tx.Value(), tx.Data()}); err != nil {
			return common.Address{}, nil, err
		}
	} else {
		if txrlp, err = rlp.EncodeToBytes([]interface{}{tx.Nonce(), tx.GasPrice(), tx.Gas(), tx.To(), tx.Value(), tx.Data(), chainID, big.NewInt(0), big.NewInt(0)}); err != nil {
			return common.Address{}, nil, err
		}
	}
	payload := append(path, txrlp...)

	// Send the request and wait for the response
	// 发送请求并等待响应
	var (
		op    = ledgerP1InitTransactionData
		reply []byte
	)

	// Chunk size selection to mitigate an underlying RLP deserialization issue on the ledger app. https://github.com/LedgerHQ/app-ethereum/issues/409
	// 选择块大小以缓解账本应用程序上潜在的 RLP 反序列化问题。 https://github.com/LedgerHQ/app-ethereum/issues/409
	chunk := 255
	for ; len(payload)%chunk <= ledgerEip155Size; chunk-- {
	}

	for len(payload) > 0 {
		// Calculate the size of the next data chunk
		// 计算下一个数据块的大小
		if chunk > len(payload) {
			chunk = len(payload)
		}
		// Send the chunk over, ensuring it's processed correctly
		// 发送块，确保它被正确处理
		reply, err = w.ledgerExchange(ledgerOpSignTransaction, op, 0, payload[:chunk])
		if err != nil {
			return common.Address{}, nil, err
		}
		// Shift the payload and ensure subsequent chunks are marked as such
		// 移动有效负载并确保后续块被标记为这样
		payload = payload[chunk:]
		op = ledgerP1ContTransactionData
	}
	// Extract the Ethereum signature and do a sanity validation
	// 提取以太坊签名并进行健全性验证
	if len(reply) != crypto.SignatureLength {
		return common.Address{}, nil, errors.New("reply lacks signature")
	}
	signature := append(reply[1:], reply[0])

	// Create the correct signer and signature transform based on the chain ID
	// 根据链 ID 创建正确的签名者和签名转换
	var signer types.Signer
	if chainID == nil {
		signer = new(types.HomesteadSigner)
	} else {
		signer = types.NewEIP155Signer(chainID)
		signature[64] -= byte(chainID.Uint64()*2 + 35)
	}
	signed, err := tx.WithSignature(signer, signature)
	if err != nil {
		return common.Address{}, nil, err
	}
	sender, err := types.Sender(signer, signed)
	if err != nil {
		return common.Address{}, nil, err
	}
	return sender, signed, nil
}

// ledgerSignTypedMessage sends the transaction to the Ledger wallet, and waits for the user to confirm or deny the transaction.
// ledgerSignTypedMessage 将交易发送到 Ledger 钱包，并等待用户确认或拒绝交易。
// The signing protocol is defined as follows:
// 签名协议定义如下：
//	CLA | INS | P1 | P2                          | Lc  | Le
//	共轭亚油酸 | INS | P1 | P2 | LC |勒
//	----+-----+----+-----------------------------+-----+---
//	E0 | 0C | 00 | implementation version : 00 | variable | variable
//	 E0 | 0C  | 00 | implementation version : 00 | variable | variable
//	 E0 | 0℃ | 00 | 00实施版本：00 |变量|多变的
// Where the input is:
// 其中输入是：
//	Description                                      | Length
//	描述 |长度
//	-------------------------------------------------+----------
//	Number of BIP 32 derivations to perform (max 10) | 1 byte
//	Number of BIP 32 derivations to perform (max 10) | 1 byte
//	要执行的 BIP 32 派生数量（最多 10）| 1字节
//	First derivation index (big endian)              | 4 bytes
//	一阶导数索引（大端）| 4字节
//	...                                              | 4 bytes
//	... | 4字节
//	Last derivation index (big endian)               | 4 bytes
//	最后派生索引（大端）| 4字节
//	domain hash                                      | 32 bytes
//	域哈希 | 32字节
//	message hash                                     | 32 bytes
//	消息哈希 | 32字节
// And the output data is:
// 输出数据为：
//	Description | Length
//	描述 |长度
//	------------+---------
//	signature V | 1 byte
//	signature V | 1 byte
//	签名V | 1字节
//	signature R | 32 bytes
//	签名R | 32字节
//	signature S | 32 bytes
//	签名 S | 32字节
func (w *ledgerDriver) ledgerSignTypedMessage(derivationPath []uint32, domainHash []byte, messageHash []byte) ([]byte, error) {
	// Flatten the derivation path into the Ledger request
	// 将派生路径扁平化为 Ledger 请求
	path := make([]byte, 1+4*len(derivationPath))
	path[0] = byte(len(derivationPath))
	for i, component := range derivationPath {
		binary.BigEndian.PutUint32(path[1+4*i:], component)
	}
	// Create the 712 message
	// 创建 712 消息
	payload := append(path, domainHash...)
	payload = append(payload, messageHash...)

	// Send the request and wait for the response
	// 发送请求并等待响应
	var (
		op    = ledgerP1InitTypedMessageData
		reply []byte
		err   error
	)

	// Send the message over, ensuring it's processed correctly
	// 发送消息，确保其得到正确处理
	reply, err = w.ledgerExchange(ledgerOpSignTypedMessage, op, 0, payload)

	if err != nil {
		return nil, err
	}

	// Extract the Ethereum signature and do a sanity validation
	// 提取以太坊签名并进行健全性验证
	if len(reply) != crypto.SignatureLength {
		return nil, errors.New("reply lacks signature")
	}
	signature := append(reply[1:], reply[0])
	return signature, nil
}

// ledgerExchange performs a data exchange with the Ledger wallet, sending it a message and retrieving the response.
// ledgerExchange 与 Ledger 钱包执行数据交换，向其发送消息并检索响应。
// The common transport header is defined as follows:
// 公共传输头定义如下：
//	Description                           | Length
//	描述 |长度
//	--------------------------------------+----------
//	Communication channel ID (big endian) | 2 bytes
//	Communication channel ID (big endian) | 2 bytes
//	通信通道 ID（大端）| 2字节
//	Command tag                           | 1 byte
//	命令标签 | 1字节
//	Packet sequence index (big endian)    | 2 bytes
//	数据包序列索引（大端）| 2字节
//	Payload                               | arbitrary
//	有效负载|随意的
// The Communication channel ID allows commands multiplexing over the same physical link. It is not used for the time being, and should be set to 0101 to avoid compatibility issues with implementations ignoring a leading 00 byte.
// 通信通道 ID 允许在同一物理链路上复用命令。暂时不使用，应设置为 0101，以避免忽略前导 00 字节的实现出现兼容性问题。
// The Command tag describes the message content. Use TAG_APDU (0x05) for standard APDU payloads, or TAG_PING (0x02) for a simple link test.
// 命令标签描述消息内容。使用 TAG_APDU (0x05) 进行标准 APDU 负载，或使用 TAG_PING (0x02) 进行简单的链路测试。
// The Packet sequence index describes the current sequence for fragmented payloads. The first fragment index is 0x00.
// 数据包序列索引描述了分段有效负载的当前序列。第一个片段索引是0x00。
// APDU Command payloads are encoded as follows:
// APDU 命令有效负载编码如下：
//	Description              | Length
//	描述 |长度
//	-----------------------------------
//	APDU length (big endian) | 2 bytes
//	APDU length (big endian) | 2 bytes
//	APDU 长度（大端）| 2字节
//	APDU CLA                 | 1 byte
//	APDU CLA | 1字节
//	APDU INS                 | 1 byte
//	APDU INS | 1字节
//	APDU P1                  | 1 byte
//	APDU P1 | 1字节
//	APDU P2                  | 1 byte
//	APDU P2 | 1字节
//	APDU length              | 1 byte
//	APDU 长度 | 1字节
//	Optional APDU data       | arbitrary
//	可选 APDU 数据 |随意的
func (w *ledgerDriver) ledgerExchange(opcode ledgerOpcode, p1 ledgerParam1, p2 ledgerParam2, data []byte) ([]byte, error) {
	// Construct the message payload, possibly split into multiple chunks
	// 构造消息有效负载，可能分为多个块
	apdu := make([]byte, 2, 7+len(data))

	binary.BigEndian.PutUint16(apdu, uint16(5+len(data)))
	apdu = append(apdu, []byte{0xe0, byte(opcode), byte(p1), byte(p2), byte(len(data))}...)
	apdu = append(apdu, data...)

	// Stream all the chunks to the device
	// 将所有块传输到设备
	header := []byte{0x01, 0x01, 0x05, 0x00, 0x00} // Channel ID and command tag appended // 附加通道 ID 和命令标签
	chunk := make([]byte, 64)
	space := len(chunk) - len(header)

	for i := 0; len(apdu) > 0; i++ {
		// Construct the new message to stream
		// 构造要流式传输的新消息
		chunk = append(chunk[:0], header...)
		binary.BigEndian.PutUint16(chunk[3:], uint16(i))

		if len(apdu) > space {
			chunk = append(chunk, apdu[:space]...)
			apdu = apdu[space:]
		} else {
			chunk = append(chunk, apdu...)
			apdu = nil
		}
		// Send over to the device
		// 发送至设备
		w.log.Trace("Data chunk sent to the Ledger", "chunk", hexutil.Bytes(chunk))
		if _, err := w.device.Write(chunk); err != nil {
			return nil, err
		}
	}
	// Stream the reply back from the wallet in 64 byte chunks
	// 以 64 字节块的形式从钱包传回回复
	var reply []byte
	chunk = chunk[:64] // Yeah, we surely have enough space // 是的，我们当然有足够的空间
	for {
		// Read the next chunk from the Ledger wallet
		// 从 Ledger 钱包中读取下一个块
		if _, err := io.ReadFull(w.device, chunk); err != nil {
			return nil, err
		}
		w.log.Trace("Data chunk received from the Ledger", "chunk", hexutil.Bytes(chunk))

		// Make sure the transport header matches
		// 确保传输标头匹配
		if chunk[0] != 0x01 || chunk[1] != 0x01 || chunk[2] != 0x05 {
			return nil, errLedgerReplyInvalidHeader
		}
		// If it's the first chunk, retrieve the total message length
		// 如果是第一个块，则检索总消息长度
		var payload []byte

		if chunk[3] == 0x00 && chunk[4] == 0x00 {
			reply = make([]byte, 0, int(binary.BigEndian.Uint16(chunk[5:7])))
			payload = chunk[7:]
		} else {
			payload = chunk[5:]
		}
		// Append to the reply and stop when filled up
		// 追加到回复中，填满后停止
		if left := cap(reply) - len(reply); left > len(payload) {
			reply = append(reply, payload...)
		} else {
			reply = append(reply, payload[:left]...)
			break
		}
	}
	return reply[:len(reply)-2], nil
}


