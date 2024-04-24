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

// This file contains the implementation for interacting with the Trezor hardware
// wallets. The wire protocol spec can be found on the SatoshiLabs website:
// https://doc.satoshilabs.com/trezor-tech/api-protobuf.html

package usbwallet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/usbwallet/trezor"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/golang/protobuf/proto"
)

// ErrTrezorPINNeeded is returned if opening the trezor requires a PIN code. In this case, the calling application should display a pinpad and send back the encoded passphrase.
// 如果打开 Trezor 需要 PIN 码，则返回 ErrTrezorPINNeeded。在这种情况下，调用应用程序应显示密码键盘并发回编码的密码。
var ErrTrezorPINNeeded = errors.New("trezor: pin needed")

// ErrTrezorPassphraseNeeded is returned if opening the trezor requires a passphrase
// 如果打开 Trezor 需要密码短语，则返回 ErrTrezorPassphraseNeeded
var ErrTrezorPassphraseNeeded = errors.New("trezor: passphrase needed")

// errTrezorReplyInvalidHeader is the error message returned by a Trezor data exchange if the device replies with a mismatching header. This usually means the device is in browser mode.
// errTrezorReplyInvalidHeader 是 Trezor 数据交换在设备回复不匹配标头时返回的错误消息。这通常意味着设备处于浏览器模式。
var errTrezorReplyInvalidHeader = errors.New("trezor: invalid reply header")

// trezorDriver implements the communication with a Trezor hardware wallet.
// trezorDriver 实现与 Trezor 硬件钱包的通信。
type trezorDriver struct {
	device         io.ReadWriter // USB device connection to communicate through // USB设备连接通过
	version        [3]uint32     // Current version of the Trezor firmware // Trezor 固件的当前版本
	label          string        // Current textual label of the Trezor device // Trezor 设备的当前文本标签
	pinwait        bool          // Flags whether the device is waiting for PIN entry // 标记设备是否正在等待 PIN 输入
	passphrasewait bool          // Flags whether the device is waiting for passphrase entry // 标记设备是否正在等待密码输入
	failure        error         // Any failure that would make the device unusable // 任何导致设备无法使用的故障
	log            log.Logger    // Contextual logger to tag the trezor with its id // 上下文记录器用其 id 标记 Trezor
}

// newTrezorDriver creates a new instance of a Trezor USB protocol driver.
// newTrezorDriver 创建 Trezor USB 协议驱动程序的新实例。
func newTrezorDriver(logger log.Logger) driver {
	return &trezorDriver{
		log: logger,
	}
}

// Status implements accounts.Wallet, always whether the Trezor is opened, closed or whether the Ethereum app was not started on it.
// Status 实现 account.Wallet，无论 Trezor 打开、关闭还是以太坊应用程序是否未在其上启动，始终如此。
func (w *trezorDriver) Status() (string, error) {
	if w.failure != nil {
		return fmt.Sprintf("Failed: %v", w.failure), w.failure
	}
	if w.device == nil {
		return "Closed", w.failure
	}
	if w.pinwait {
		return fmt.Sprintf("Trezor v%d.%d.%d '%s' waiting for PIN", w.version[0], w.version[1], w.version[2], w.label), w.failure
	}
	return fmt.Sprintf("Trezor v%d.%d.%d '%s' online", w.version[0], w.version[1], w.version[2], w.label), w.failure
}

// Open implements usbwallet.driver, attempting to initialize the connection to the Trezor hardware wallet. Initializing the Trezor is a two or three phase operation:
// Open 实现 usbwallet.driver，尝试初始化与 Trezor 硬件钱包的连接。初始化 Trezor 是一个两阶段或三相操作：
//   - The first phase is to initialize the connection and read the wallet's
//   - 第一阶段是初始化连接并读取钱包的
//     features. This phase is invoked if the provided passphrase is empty. The
//     特征。如果提供的密码为空，则调用此阶段。这
//     device will display the pinpad as a result and will return an appropriate
//     设备将显示密码键盘结果并返回适当的
//     error to notify the user that a second open phase is needed.
//     错误通知用户需要第二个打开阶段。
//   - The second phase is to unlock access to the Trezor, which is done by the
//   - 第二阶段是解锁对 Trezor 的访问，这是由
//     user actually providing a passphrase mapping a keyboard keypad to the pin
//     用户实际上提供了一个将键盘小键盘映射到 pin 的密码
//     number of the user (shuffled according to the pinpad displayed).
//     用户号码（根据显示的密码键盘随机排列）。
//   - If needed the device will ask for passphrase which will require calling
//   - 如果需要，设备将要求输入密码，这需要致电
//     open again with the actual passphrase (3rd phase)
//     使用实际密码再次打开（第三阶段）
func (w *trezorDriver) Open(device io.ReadWriter, passphrase string) error {
	w.device, w.failure = device, nil

	// If phase 1 is requested, init the connection and wait for user callback
	// 如果请求阶段 1，则初始化连接并等待用户回调
	if passphrase == "" && !w.passphrasewait {
		// If we're already waiting for a PIN entry, insta-return
		// 如果我们已经在等待 PIN 输入，请立即返回
		if w.pinwait {
			return ErrTrezorPINNeeded
		}
		// Initialize a connection to the device
		// 初始化与设备的连接
		features := new(trezor.Features)
		if _, err := w.trezorExchange(&trezor.Initialize{}, features); err != nil {
			return err
		}
		w.version = [3]uint32{features.GetMajorVersion(), features.GetMinorVersion(), features.GetPatchVersion()}
		w.label = features.GetLabel()

		// Do a manual ping, forcing the device to ask for its PIN and Passphrase
		// 执行手动 ping，强制设备询问其 PIN 和密码
		askPin := true
		askPassphrase := true
		res, err := w.trezorExchange(&trezor.Ping{PinProtection: &askPin, PassphraseProtection: &askPassphrase}, new(trezor.PinMatrixRequest), new(trezor.PassphraseRequest), new(trezor.Success))
		if err != nil {
			return err
		}
		// Only return the PIN request if the device wasn't unlocked until now
		// 仅当设备目前尚未解锁时才返回 PIN 请求
		switch res {
		case 0:
			w.pinwait = true
			return ErrTrezorPINNeeded
		case 1:
			w.pinwait = false
			w.passphrasewait = true
			return ErrTrezorPassphraseNeeded
		case 2:
			return nil // responded with trezor.Success // 回复 Trezor。成功
		}
	}
	// Phase 2 requested with actual PIN entry
	// 第 2 阶段请求输入实际 PIN 码
	if w.pinwait {
		w.pinwait = false
		res, err := w.trezorExchange(&trezor.PinMatrixAck{Pin: &passphrase}, new(trezor.Success), new(trezor.PassphraseRequest))
		if err != nil {
			w.failure = err
			return err
		}
		if res == 1 {
			w.passphrasewait = true
			return ErrTrezorPassphraseNeeded
		}
	} else if w.passphrasewait {
		w.passphrasewait = false
		if _, err := w.trezorExchange(&trezor.PassphraseAck{Passphrase: &passphrase}, new(trezor.Success)); err != nil {
			w.failure = err
			return err
		}
	}

	return nil
}

// Close implements usbwallet.driver, cleaning up and metadata maintained within the Trezor driver.
// Close 实现了 usbwallet.driver，清理并在 Trezor 驱动程序中维护元数据。
func (w *trezorDriver) Close() error {
	w.version, w.label, w.pinwait = [3]uint32{}, "", false
	return nil
}

// Heartbeat implements usbwallet.driver, performing a sanity check against the Trezor to see if it's still online.
// Heartbeat 实现了 usbwallet.driver，对 Trezor 执行健全性检查以查看它是否仍然在线。
func (w *trezorDriver) Heartbeat() error {
	if _, err := w.trezorExchange(&trezor.Ping{}, new(trezor.Success)); err != nil {
		w.failure = err
		return err
	}
	return nil
}

// Derive implements usbwallet.driver, sending a derivation request to the Trezor and returning the Ethereum address located on that derivation path.
// Derive 实现 usbwallet.driver，向 Trezor 发送派生请求并返回位于该派生路径上的以太坊地址。
func (w *trezorDriver) Derive(path accounts.DerivationPath) (common.Address, error) {
	return w.trezorDerive(path)
}

// SignTx implements usbwallet.driver, sending the transaction to the Trezor and waiting for the user to confirm or deny the transaction.
// SignTx 实现 usbwallet.driver，将交易发送到 Trezor 并等待用户确认或拒绝交易。
func (w *trezorDriver) SignTx(path accounts.DerivationPath, tx *types.Transaction, chainID *big.Int) (common.Address, *types.Transaction, error) {
	if w.device == nil {
		return common.Address{}, nil, accounts.ErrWalletClosed
	}
	return w.trezorSign(path, tx, chainID)
}

func (w *trezorDriver) SignTypedMessage(path accounts.DerivationPath, domainHash []byte, messageHash []byte) ([]byte, error) {
	return nil, accounts.ErrNotSupported
}

// trezorDerive sends a derivation request to the Trezor device and returns the Ethereum address located on that path.
// trezorDerive 向 Trezor 设备发送派生请求并返回位于该路径上的以太坊地址。
func (w *trezorDriver) trezorDerive(derivationPath []uint32) (common.Address, error) {
	address := new(trezor.EthereumAddress)
	if _, err := w.trezorExchange(&trezor.EthereumGetAddress{AddressN: derivationPath}, address); err != nil {
		return common.Address{}, err
	}
	if addr := address.GetAddressBin(); len(addr) > 0 { // Older firmwares use binary formats // 较旧的固件使用二进制格式
		return common.BytesToAddress(addr), nil
	}
	if addr := address.GetAddressHex(); len(addr) > 0 { // Newer firmwares use hexadecimal formats // 较新的固件使用十六进制格式
		return common.HexToAddress(addr), nil
	}
	return common.Address{}, errors.New("missing derived address")
}

// trezorSign sends the transaction to the Trezor wallet, and waits for the user to confirm or deny the transaction.
// trezorSign 将交易发送到 Trezor 钱包，并等待用户确认或拒绝交易。
func (w *trezorDriver) trezorSign(derivationPath []uint32, tx *types.Transaction, chainID *big.Int) (common.Address, *types.Transaction, error) {
	// Create the transaction initiation message
	// 创建交易发起消息
	data := tx.Data()
	length := uint32(len(data))

	request := &trezor.EthereumSignTx{
		AddressN:   derivationPath,
		Nonce:      new(big.Int).SetUint64(tx.Nonce()).Bytes(),
		GasPrice:   tx.GasPrice().Bytes(),
		GasLimit:   new(big.Int).SetUint64(tx.Gas()).Bytes(),
		Value:      tx.Value().Bytes(),
		DataLength: &length,
	}
	if to := tx.To(); to != nil {
		// Non contract deploy, set recipient explicitly
		// 非合约部署，明确设置接收者
		hex := to.Hex()
		request.ToHex = &hex     // Newer firmwares (old will ignore) // 较新的固件（旧的将被忽略）
		request.ToBin = (*to)[:] // Older firmwares (new will ignore) // 旧固件（新固件将忽略）
	}
	if length > 1024 { // Send the data chunked if that was requested // 如果有请求，则发送分块数据
		request.DataInitialChunk, data = data[:1024], data[1024:]
	} else {
		request.DataInitialChunk, data = data, nil
	}
	if chainID != nil { // EIP-155 transaction, set chain ID explicitly (only 32 bit is supported!?) // EIP-155交易，显式设置链ID（仅支持32位！？）
		id := uint32(chainID.Int64())
		request.ChainId = &id
	}
	// Send the initiation message and stream content until a signature is returned
	// 发送启动消息和流内容，直到返回签名
	response := new(trezor.EthereumTxRequest)
	if _, err := w.trezorExchange(request, response); err != nil {
		return common.Address{}, nil, err
	}
	for response.DataLength != nil && int(*response.DataLength) <= len(data) {
		chunk := data[:*response.DataLength]
		data = data[*response.DataLength:]

		if _, err := w.trezorExchange(&trezor.EthereumTxAck{DataChunk: chunk}, response); err != nil {
			return common.Address{}, nil, err
		}
	}
	// Extract the Ethereum signature and do a sanity validation
	// 提取以太坊签名并进行健全性验证
	if len(response.GetSignatureR()) == 0 || len(response.GetSignatureS()) == 0 || response.GetSignatureV() == 0 {
		return common.Address{}, nil, errors.New("reply lacks signature")
	}
	signature := append(append(response.GetSignatureR(), response.GetSignatureS()...), byte(response.GetSignatureV()))

	// Create the correct signer and signature transform based on the chain ID
	// 根据链 ID 创建正确的签名者和签名转换
	var signer types.Signer
	if chainID == nil {
		signer = new(types.HomesteadSigner)
	} else {
		// Trezor backend does not support typed transactions yet.
		// Trezor 后端尚不支持类型化交易。
		signer = types.NewEIP155Signer(chainID)
		signature[64] -= byte(chainID.Uint64()*2 + 35)
	}

	// Inject the final signature into the transaction and sanity check the sender
	// 将最终签名注入交易并对发送者进行健全性检查
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

// trezorExchange performs a data exchange with the Trezor wallet, sending it a message and retrieving the response. If multiple responses are possible, the method will also return the index of the destination object used.
// trezorExchange 与 Trezor 钱包执行数据交换，向其发送消息并检索响应。如果可能有多个响应，该方法还将返回所使用的目标对象的索引。
func (w *trezorDriver) trezorExchange(req proto.Message, results ...proto.Message) (int, error) {
	// Construct the original message payload to chunk up
	// 构造原始消息有效负载以进行分块
	data, err := proto.Marshal(req)
	if err != nil {
		return 0, err
	}
	payload := make([]byte, 8+len(data))
	copy(payload, []byte{0x23, 0x23})
	binary.BigEndian.PutUint16(payload[2:], trezor.Type(req))
	binary.BigEndian.PutUint32(payload[4:], uint32(len(data)))
	copy(payload[8:], data)

	// Stream all the chunks to the device
	// 将所有块传输到设备
	chunk := make([]byte, 64)
	chunk[0] = 0x3f // Report ID magic number // 报告 ID 幻数

	for len(payload) > 0 {
		// Construct the new message to stream, padding with zeroes if needed
		// 构造要流式传输的新消息，如果需要则用零填充
		if len(payload) > 63 {
			copy(chunk[1:], payload[:63])
			payload = payload[63:]
		} else {
			copy(chunk[1:], payload)
			copy(chunk[1+len(payload):], make([]byte, 63-len(payload)))
			payload = nil
		}
		// Send over to the device
		// 发送至设备
		w.log.Trace("Data chunk sent to the Trezor", "chunk", hexutil.Bytes(chunk))
		if _, err := w.device.Write(chunk); err != nil {
			return 0, err
		}
	}
	// Stream the reply back from the wallet in 64 byte chunks
	// 以 64 字节块的形式从钱包传回回复
	var (
		kind  uint16
		reply []byte
	)
	for {
		// Read the next chunk from the Trezor wallet
		// 从 Trezor 钱包中读取下一个块
		if _, err := io.ReadFull(w.device, chunk); err != nil {
			return 0, err
		}
		w.log.Trace("Data chunk received from the Trezor", "chunk", hexutil.Bytes(chunk))

		// Make sure the transport header matches
		// 确保传输标头匹配
		if chunk[0] != 0x3f || (len(reply) == 0 && (chunk[1] != 0x23 || chunk[2] != 0x23)) {
			return 0, errTrezorReplyInvalidHeader
		}
		// If it's the first chunk, retrieve the reply message type and total message length
		// 如果是第一个块，则检索回复消息类型和消息总长度
		var payload []byte

		if len(reply) == 0 {
			kind = binary.BigEndian.Uint16(chunk[3:5])
			reply = make([]byte, 0, int(binary.BigEndian.Uint32(chunk[5:9])))
			payload = chunk[9:]
		} else {
			payload = chunk[1:]
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
	// Try to parse the reply into the requested reply message
	// 尝试将回复解析为请求的回复消息
	if kind == uint16(trezor.MessageType_MessageType_Failure) {
		// Trezor returned a failure, extract and return the message
		// Trezor返回失败，提取并返回消息
		failure := new(trezor.Failure)
		if err := proto.Unmarshal(reply, failure); err != nil {
			return 0, err
		}
		return 0, errors.New("trezor: " + failure.GetMessage())
	}
	if kind == uint16(trezor.MessageType_MessageType_ButtonRequest) {
		// Trezor is waiting for user confirmation, ack and wait for the next message
		// Trezor正在等待用户确认，ack并等待下一条消息
		return w.trezorExchange(&trezor.ButtonAck{}, results...)
	}
	for i, res := range results {
		if trezor.Type(res) == kind {
			return i, proto.Unmarshal(reply, res)
		}
	}
	expected := make([]string, len(results))
	for i, res := range results {
		expected[i] = trezor.Name(trezor.Type(res))
	}
	return 0, fmt.Errorf("trezor: expected reply types %s, got %s", expected, trezor.Name(kind))
}


