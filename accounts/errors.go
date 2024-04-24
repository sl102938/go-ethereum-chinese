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

package accounts

import (
	"errors"
	"fmt"
)

// ErrUnknownAccount is returned for any requested operation for which no backend provides the specified account.
// 对于任何没有后端提供指定帐户的请求操作，都会返回 ErrUnknownAccount。
var ErrUnknownAccount = errors.New("unknown account")

// ErrUnknownWallet is returned for any requested operation for which no backend provides the specified wallet.
// 对于任何没有后端提供指定钱包的请求操作，都会返回 ErrUnknownWallet。
var ErrUnknownWallet = errors.New("unknown wallet")

// ErrNotSupported is returned when an operation is requested from an account backend that it does not support.
// 当从不支持的账户后端请求操作时，会返回 ErrNotSupported。
var ErrNotSupported = errors.New("not supported")

// ErrInvalidPassphrase is returned when a decryption operation receives a bad passphrase.
// 当解密操作收到错误的密码时，将返回 ErrInvalidPassphrase。
var ErrInvalidPassphrase = errors.New("invalid password")

// ErrWalletAlreadyOpen is returned if a wallet is attempted to be opened the second time.
// 如果第二次尝试打开钱包，则会返回 ErrWalletAlreadyOpen。
var ErrWalletAlreadyOpen = errors.New("wallet already open")

// ErrWalletClosed is returned if a wallet is offline.
// 如果钱包离线，则返回 ErrWalletClosed。
var ErrWalletClosed = errors.New("wallet closed")

// AuthNeededError is returned by backends for signing requests where the user is required to provide further authentication before signing can succeed.
// AuthNeededError 由后端针对签名请求返回，其中用户需要提供进一步的身份验证才能成功签名。
// This usually means either that a password needs to be supplied, or perhaps a one time PIN code displayed by some hardware device.
// 这通常意味着需要提供密码，或者可能是某些硬件设备显示的一次性 PIN 码。
type AuthNeededError struct {
	Needed string // Extra authentication the user needs to provide // 用户需要提供额外的身份验证
}

// NewAuthNeededError creates a new authentication error with the extra details about the needed fields set.
// NewAuthNeededError 创建一个新的身份验证错误，其中包含有关所需字段集的额外详细信息。
func NewAuthNeededError(needed string) error {
	return &AuthNeededError{
		Needed: needed,
	}
}

// Error implements the standard error interface.
// Error 实现了标准错误接口。
func (err *AuthNeededError) Error() string {
	return fmt.Sprintf("authentication needed: %s", err.Needed)
}


