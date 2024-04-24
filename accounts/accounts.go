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

// Package accounts implements high level Ethereum account management.
package accounts

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"golang.org/x/crypto/sha3"
)

// Account represents an Ethereum account located at a specific location defined by the optional URL field.
// 帐户表示位于由可选 URL 字段定义的特定位置的以太坊帐户。
type Account struct {
	Address common.Address `json:"address"` // Ethereum account address derived from the key // 从密钥导出的以太坊账户地址
	URL     URL            `json:"url"`     // Optional resource locator within a backend // 后端内的可选资源定位器
}

const (
	MimetypeDataWithValidator = "data/validator"
	MimetypeTypedData         = "data/typed"
	MimetypeClique            = "application/x-clique-header"
	MimetypeTextPlain         = "text/plain"
)

// Wallet represents a software or hardware wallet that might contain one or more accounts (derived from the same seed).
// 钱包代表一种软件或硬件钱包，可能包含一个或多个帐户（源自同一种子）。
type Wallet interface {
	// URL retrieves the canonical path under which this wallet is reachable. It is used by upper layers to define a sorting order over all wallets from multiple backends.
	// URL 检索可访问此钱包的规范路径。上层使用它来定义来自多个后端的所有钱包的排序顺序。
	URL() URL

	// Status returns a textual status to aid the user in the current state of the wallet. It also returns an error indicating any failure the wallet might have encountered.
	// Status 返回文本状态以帮助用户了解钱包的当前状态。它还返回一个错误，指示钱包可能遇到的任何故障。
	Status() (string, error)

	// Open initializes access to a wallet instance. It is not meant to unlock or decrypt account keys, rather simply to establish a connection to hardware wallets and/or to access derivation seeds.
	// Open 初始化对钱包实例的访问。它并不是为了解锁或解密帐户密钥，而只是为了建立与硬件钱包的连接和/或访问派生种子。
	// The passphrase parameter may or may not be used by the implementation of a particular wallet instance. The reason there is no passwordless open method is to strive towards a uniform wallet handling, oblivious to the different backend providers.
	// 特定钱包实例的实现可能会或可能不会使用密码参数。没有无密码打开方法的原因是努力实现统一的钱包处理，忽略不同的后端提供商。
	// Please note, if you open a wallet, you must close it to release any allocated resources (especially important when working with hardware wallets).
	// 请注意，如果您打开钱包，则必须将其关闭以释放任何分配的资源（在使用硬件钱包时尤其重要）。
	Open(passphrase string) error

	// Close releases any resources held by an open wallet instance.
	// 关闭会释放打开的钱包实例持有的所有资源。
	Close() error

	// Accounts retrieves the list of signing accounts the wallet is currently aware of. For hierarchical deterministic wallets, the list will not be exhaustive, rather only contain the accounts explicitly pinned during account derivation.
	// 帐户检索钱包当前已知的签名帐户列表。对于分层确定性钱包，该列表不会是详尽的，而是仅包含在帐户派生过程中明确固定的帐户。
	Accounts() []Account

	// Contains returns whether an account is part of this particular wallet or not.
	// 包含返回值，无论帐户是否属于该特定钱包。
	Contains(account Account) bool

	// Derive attempts to explicitly derive a hierarchical deterministic account at the specified derivation path. If requested, the derived account will be added to the wallet's tracked account list.
	// 派生尝试在指定的派生路径上显式派生分层确定性帐户。如果需要，派生帐户将被添加到钱包的跟踪帐户列表中。
	Derive(path DerivationPath, pin bool) (Account, error)

	// SelfDerive sets a base account derivation path from which the wallet attempts to discover non zero accounts and automatically add them to list of tracked accounts.
	// SelfDerive 设置基本帐户派生路径，钱包尝试从中发现非零帐户并自动将它们添加到跟踪帐户列表中。
	// Note, self derivation will increment the last component of the specified path opposed to descending into a child path to allow discovering accounts starting from non zero components.
	// 请注意，自派生将增加指定路径的最后一个组件，而不是下降到子路径，以允许从非零组件开始发现帐户。
	// Some hardware wallets switched derivation paths through their evolution, so this method supports providing multiple bases to discover old user accounts too. Only the last base will be used to derive the next empty account.
	// 一些硬件钱包在演变过程中改变了派生路径，因此该方法也支持提供多个基础来发现旧用户帐户。仅最后一个基数将用于派生下一个空帐户。
	// You can disable automatic account discovery by calling SelfDerive with a nil chain state reader.
	// 您可以通过使用 nil 链状态读取器调用 SelfDerive 来禁用自动帐户发现。
	SelfDerive(bases []DerivationPath, chain ethereum.ChainStateReader)

	// SignData requests the wallet to sign the hash of the given data It looks up the account specified either solely via its address contained within, or optionally with the aid of any location metadata from the embedded URL field.
	// SignData 请求钱包对给定数据的哈希进行签名。它仅通过其中包含的地址查找指定的帐户，也可以选择借助嵌入 URL 字段中的任何位置元数据。
	// If the wallet requires additional authentication to sign the request (e.g. a password to decrypt the account, or a PIN code to verify the transaction), an AuthNeededError instance will be returned, containing infos for the user about which fields or actions are needed. The user may retry by providing the needed details via SignDataWithPassphrase, or by other means (e.g. unlock the account in a keystore).
	// 如果钱包需要额外的身份验证来签署请求（例如用于解密帐户的密码，或用于验证交易的 PIN 码），则将返回 AuthNeededError 实例，其中包含用户需要哪些字段或操作的信息。用户可以通过 SignDataWithPassphrase 提供所需的详细信息或通过其他方式（例如在密钥库中解锁帐户）来重试。
	SignData(account Account, mimeType string, data []byte) ([]byte, error)

	// SignDataWithPassphrase is identical to SignData, but also takes a password NOTE: there's a chance that an erroneous call might mistake the two strings, and supply password in the mimetype field, or vice versa. Thus, an implementation should never echo the mimetype or return the mimetype in the error-response
	// SignDataWithPassphrase 与 SignData 相同，但也需要密码注意：错误的调用有可能会弄错两个字符串，并在 mimetype 字段中提供密码，反之亦然。因此，实现永远不应该回显 mimetype 或在错误响应中返回 mimetype
	SignDataWithPassphrase(account Account, passphrase, mimeType string, data []byte) ([]byte, error)

	// SignText requests the wallet to sign the hash of a given piece of data, prefixed by the Ethereum prefix scheme It looks up the account specified either solely via its address contained within, or optionally with the aid of any location metadata from the embedded URL field.
	// SignText 请求钱包对给定数据的哈希进行签名，该数据以以太坊前缀方案为前缀。它仅通过其中包含的地址查找指定的帐户，也可以选择借助嵌入 URL 字段中的任何位置元数据。
	// If the wallet requires additional authentication to sign the request (e.g. a password to decrypt the account, or a PIN code to verify the transaction), an AuthNeededError instance will be returned, containing infos for the user about which fields or actions are needed. The user may retry by providing the needed details via SignTextWithPassphrase, or by other means (e.g. unlock the account in a keystore).
	// 如果钱包需要额外的身份验证来签署请求（例如用于解密帐户的密码，或用于验证交易的 PIN 码），则将返回 AuthNeededError 实例，其中包含用户需要哪些字段或操作的信息。用户可以通过 SignTextWithPassphrase 提供所需的详细信息或通过其他方式（例如在密钥库中解锁帐户）来重试。
	// This method should return the signature in 'canonical' format, with v 0 or 1.
	// 此方法应返回“规范”格式的签名，其中 v 为 0 或 1。
	SignText(account Account, text []byte) ([]byte, error)

	// SignTextWithPassphrase is identical to Signtext, but also takes a password
	// SignTextWithPassphrase 与 Signtext 相同，但也需要密码
	SignTextWithPassphrase(account Account, passphrase string, hash []byte) ([]byte, error)

	// SignTx requests the wallet to sign the given transaction.
	// SignTx 请求钱包签署给定的交易。
	// It looks up the account specified either solely via its address contained within, or optionally with the aid of any location metadata from the embedded URL field.
	// 它可以仅通过其中包含的地址查找指定的帐户，也可以选择借助嵌入的 URL 字段中的任何位置元数据来查找指定的帐户。
	// If the wallet requires additional authentication to sign the request (e.g. a password to decrypt the account, or a PIN code to verify the transaction), an AuthNeededError instance will be returned, containing infos for the user about which fields or actions are needed. The user may retry by providing the needed details via SignTxWithPassphrase, or by other means (e.g. unlock the account in a keystore).
	// 如果钱包需要额外的身份验证来签署请求（例如用于解密帐户的密码，或用于验证交易的 PIN 码），则将返回 AuthNeededError 实例，其中包含用户需要哪些字段或操作的信息。用户可以通过 SignTxWithPassphrase 提供所需的详细信息或通过其他方式（例如在密钥库中解锁帐户）来重试。
	SignTx(account Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)

	// SignTxWithPassphrase is identical to SignTx, but also takes a password
	// SignTxWithPassphrase 与 SignTx 相同，但也需要密码
	SignTxWithPassphrase(account Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
}

// Backend is a "wallet provider" that may contain a batch of accounts they can sign transactions with and upon request, do so.
// 后端是一个“钱包提供商”，可能包含一批可以用来签署交易的帐户，并根据请求执行此操作。
type Backend interface {
	// Wallets retrieves the list of wallets the backend is currently aware of.
	// 钱包检索后端当前知道的钱包列表。
	// The returned wallets are not opened by default. For software HD wallets this means that no base seeds are decrypted, and for hardware wallets that no actual connection is established.
	// 返回的钱包默认不打开。对于软件 HD 钱包，这意味着没有基础种子被解密，对于硬件钱包来说，没有建立实际连接。
	// The resulting wallet list will be sorted alphabetically based on its internal URL assigned by the backend. Since wallets (especially hardware) may come and go, the same wallet might appear at a different positions in the list during subsequent retrievals.
	// 生成的钱包列表将根据后端分配的内部 URL 按字母顺序排序。由于钱包（尤其是硬件）可能会出现和消失，因此在后续检索过程中，同一个钱包可能会出现在列表中的不同位置。
	Wallets() []Wallet

	// Subscribe creates an async subscription to receive notifications when the backend detects the arrival or departure of a wallet.
	// Subscribe 创建一个异步订阅，以便在后端检测到钱包到达或离开时接收通知。
	Subscribe(sink chan<- WalletEvent) event.Subscription
}

// TextHash is a helper function that calculates a hash for the given message that can be safely used to calculate a signature from.
// TextHash 是一个辅助函数，用于计算给定消息的哈希值，该哈希值可安全地用于计算签名。
// The hash is calculated as
// 哈希计算如下
//	keccak256("\x19Ethereum Signed Message:\n"${message length}${message}).
//	keccak256("\x19以太坊签名消息:\n"${消息长度}${消息}).
// This gives context to the signed message and prevents signing of transactions.
// 这为签名消息提供了上下文并阻止交易签名。
func TextHash(data []byte) []byte {
	hash, _ := TextAndHash(data)
	return hash
}

// TextAndHash is a helper function that calculates a hash for the given message that can be safely used to calculate a signature from.
// TextAndHash 是一个辅助函数，用于计算给定消息的哈希值，该哈希值可安全地用于计算签名。
// The hash is calculated as
// 哈希计算如下
//	keccak256("\x19Ethereum Signed Message:\n"${message length}${message}).
//	keccak256("\x19以太坊签名消息:\n"${消息长度}${消息}).
// This gives context to the signed message and prevents signing of transactions.
// 这为签名消息提供了上下文并阻止交易签名。
func TextAndHash(data []byte) ([]byte, string) {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(msg))
	return hasher.Sum(nil), msg
}

// WalletEventType represents the different event types that can be fired by the wallet subscription subsystem.
// WalletEventType 表示钱包订阅子系统可以触发的不同事件类型。
type WalletEventType int

const (
	// WalletArrived is fired when a new wallet is detected either via USB or via a filesystem event in the keystore.
	// 当通过 USB 或通过密钥库中的文件系统事件检测到新钱包时，WalletArrived 会被触发。
	WalletArrived WalletEventType = iota

	// WalletOpened is fired when a wallet is successfully opened with the purpose of starting any background processes such as automatic key derivation.
	// 当成功打开钱包以启动任何后台进程（例如自动密钥派生）时，将触发 WalletOpened。
	WalletOpened

	// WalletDropped
	// 钱包掉落
	WalletDropped
)

// WalletEvent is an event fired by an account backend when a wallet arrival or departure is detected.
// WalletEvent 是当检测到钱包到达或离开时由帐户后端触发的事件。
type WalletEvent struct {
	Wallet Wallet          // Wallet instance arrived or departed // 钱包实例到达或离开
	Kind   WalletEventType // Event type that happened in the system // 系统中发生的事件类型
}


