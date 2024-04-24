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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// URL represents the canonical identification URL of a wallet or account.
// URL代表钱包或账户的规范标识URL。
// It is a simplified version of url.URL, with the important limitations (which are considered features here) that it contains value-copyable components only, as well as that it doesn't do any URL encoding/decoding of special characters.
// 它是 url.URL 的简化版本，具有重要的限制（此处被视为功能）：它仅包含可复制值的组件，并且它不执行任何特殊字符的 URL 编码/解码。
// The former is important to allow an account to be copied without leaving live references to the original version, whereas the latter is important to ensure one single canonical form opposed to many allowed ones by the RFC 3986 spec.
// 前者对于允许复制帐户而不留下对原始版本的实时引用非常重要，而后者对于确保与 RFC 3986 规范允许的许多形式相反的单一规范形式非常重要。
// As such, these URLs should not be used outside of the scope of an Ethereum wallet or account.
// 因此，这些 URL 不应在以太坊钱包或帐户范围之外使用。
type URL struct {
	Scheme string // Protocol scheme to identify a capable account backend // 用于识别有能力的帐户后端的协议方案
	Path   string // Path for the backend to identify a unique entity // 后端识别唯一实体的路径
}

// parseURL converts a user supplied URL into the accounts specific structure.
// parseURL 将用户提供的 URL 转换为帐户特定的结构。
func parseURL(url string) (URL, error) {
	parts := strings.Split(url, "://")
	if len(parts) != 2 || parts[0] == "" {
		return URL{}, errors.New("protocol scheme missing")
	}
	return URL{
		Scheme: parts[0],
		Path:   parts[1],
	}, nil
}

// String implements the stringer interface.
// String 实现了 stringer 接口。
func (u URL) String() string {
	if u.Scheme != "" {
		return fmt.Sprintf("%s://%s", u.Scheme, u.Path)
	}
	return u.Path
}

// TerminalString implements the log.TerminalStringer interface.
// TerminalString 实现 log.TerminalStringer 接口。
func (u URL) TerminalString() string {
	url := u.String()
	if len(url) > 32 {
		return url[:31] + ".."
	}
	return url
}

// MarshalJSON implements the json.Marshaller interface.
// MarshalJSON 实现 json.Marshaller 接口。
func (u URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

// UnmarshalJSON parses url.
// UnmarshalJSON 解析 url。
func (u *URL) UnmarshalJSON(input []byte) error {
	var textURL string
	err := json.Unmarshal(input, &textURL)
	if err != nil {
		return err
	}
	url, err := parseURL(textURL)
	if err != nil {
		return err
	}
	u.Scheme = url.Scheme
	u.Path = url.Path
	return nil
}

// Cmp compares x and y and returns:
// Cmp 比较 x 和 y 并返回：
//	-1 if x <  y
//	-1 如果 x `<` y
//	 0 if x == y
//	 0 如果 x == y
//	+1 if x >  y
//	+1 如果 x > y
func (u URL) Cmp(url URL) int {
	if u.Scheme == url.Scheme {
		return strings.Compare(u.Path, url.Path)
	}
	return strings.Compare(u.Scheme, url.Scheme)
}


