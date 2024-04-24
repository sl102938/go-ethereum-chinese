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
	"math"
	"math/big"
	"strings"
)

// DefaultRootDerivationPath is the root path to which custom derivation endpoints are appended. As such, the first account will be at m/44'/60'/0'/0, the second at m/44'/60'/0'/1, etc.
// DefaultRootDerivationPath 是附加自定义派生端点的根路径。因此，第一个帐户将位于 m/44'/60'/0'/0，第二个帐户将位于 m/44'/60'/0'/1，依此类推。
var DefaultRootDerivationPath = DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0}

// DefaultBaseDerivationPath is the base path from which custom derivation endpoints are incremented. As such, the first account will be at m/44'/60'/0'/0/0, the second at m/44'/60'/0'/0/1, etc.
// DefaultBaseDerivationPath 是自定义派生端点从中递增的基本路径。因此，第一个帐户将位于 m/44'/60'/0'/0/0，第二个帐户将位于 m/44'/60'/0'/0/1，依此类推。
var DefaultBaseDerivationPath = DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0}

// LegacyLedgerBaseDerivationPath is the legacy base path from which custom derivation endpoints are incremented. As such, the first account will be at m/44'/60'/0'/0, the second at m/44'/60'/0'/1, etc.
// LegacyLedgerBaseDerivationPath 是传统基本路径，自定义派生端点从该路径递增。因此，第一个帐户将位于 m/44'/60'/0'/0，第二个帐户将位于 m/44'/60'/0'/1，依此类推。
var LegacyLedgerBaseDerivationPath = DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0}

// DerivationPath represents the computer friendly version of a hierarchical deterministic wallet account derivation path.
// DerivationPath 表示分层确定性钱包帐户派生路径的计算机友好版本。
// The BIP-32 spec https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki defines derivation paths to be of the form:
// BIP-32 规范 https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki 将派生路径定义为以下形式：
//	m / purpose' / coin_type' / account' / change / address_index
//	m/目的'/coin_type'/账户'/change/address_index
// The BIP-44 spec https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki defines that the `purpose` be 44' (or 0x8000002C) for crypto currencies, and SLIP-44 https://github.com/satoshilabs/slips/blob/master/slip-0044.md assigns the `coin_type` 60' (or 0x8000003C) to Ethereum.
// BIP-44 规范 https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki 定义加密货币的“目的”为 44（或 0x8000002C），而 SLIP-44 https:// /github.com/satoshilabs/slips/blob/master/slip-0044.md 将 `coin_type` 60' （或 0x8000003C）分配给以太坊。
// The root path for Ethereum is m/44'/60'/0'/0 according to the specification from https://github.com/ethereum/EIPs/issues/84, albeit it's not set in stone yet whether accounts should increment the last component or the children of that. We will go with the simpler approach of incrementing the last component.
// 根据 https://github.com/ethereum/EIPs/issues/84 的规范，以太坊的根路径是 m/44'/60'/0'/0，尽管还没有确定帐户是否应该增加最后一个组件或其子组件。我们将采用更简单的方法来增加最后一个组件。
type DerivationPath []uint32

// ParseDerivationPath converts a user specified derivation path string to the internal binary representation.
// ParseDerivationPath 将用户指定的派生路径字符串转换为内部二进制表示形式。
// Full derivation paths need to start with the `m/` prefix, relative derivation paths (which will get appended to the default root path) must not have prefixes in front of the first element. Whitespace is ignored.
// 完整派生路径需要以“m/”前缀开头，相对派生路径（将附加到默认根路径）在第一个元素前面不得有前缀。空白将被忽略。
func ParseDerivationPath(path string) (DerivationPath, error) {
	var result DerivationPath

	// Handle absolute or relative paths
	// 处理绝对或相对路径
	components := strings.Split(path, "/")
	switch {
	case len(components) == 0:
		return nil, errors.New("empty derivation path")

	case strings.TrimSpace(components[0]) == "":
		return nil, errors.New("ambiguous path: use 'm/' prefix for absolute paths, or no leading '/' for relative ones")

	case strings.TrimSpace(components[0]) == "m":
		components = components[1:]

	default:
		result = append(result, DefaultRootDerivationPath...)
	}
	// All remaining components are relative, append one by one
	// 其余所有组件都是相对的，一一附加
	if len(components) == 0 {
		return nil, errors.New("empty derivation path") // Empty relative paths // 空相对路径
	}
	for _, component := range components {
		// Ignore any user added whitespace
		// 忽略任何用户添加的空格
		component = strings.TrimSpace(component)
		var value uint32

		// Handle hardened paths
		// 处理硬化路径
		if strings.HasSuffix(component, "'") {
			value = 0x80000000
			component = strings.TrimSpace(strings.TrimSuffix(component, "'"))
		}
		// Handle the non hardened component
		// 处理非硬化部件
		bigval, ok := new(big.Int).SetString(component, 0)
		if !ok {
			return nil, fmt.Errorf("invalid component: %s", component)
		}
		max := math.MaxUint32 - value
		if bigval.Sign() < 0 || bigval.Cmp(big.NewInt(int64(max))) > 0 {
			if value == 0 {
				return nil, fmt.Errorf("component %v out of allowed range [0, %d]", bigval, max)
			}
			return nil, fmt.Errorf("component %v out of allowed hardened range [0, %d]", bigval, max)
		}
		value += uint32(bigval.Uint64())

		// Append and repeat
		// 追加并重复
		result = append(result, value)
	}
	return result, nil
}

// String implements the stringer interface, converting a binary derivation path to its canonical representation.
// String 实现了 stringer 接口，将二进制派生路径转换为其规范表示形式。
func (path DerivationPath) String() string {
	result := "m"
	for _, component := range path {
		var hardened bool
		if component >= 0x80000000 {
			component -= 0x80000000
			hardened = true
		}
		result = fmt.Sprintf("%s/%d", result, component)
		if hardened {
			result += "'"
		}
	}
	return result
}

// MarshalJSON turns a derivation path into its json-serialized string
// MarshalJSON 将派生路径转换为其 json 序列化字符串
func (path DerivationPath) MarshalJSON() ([]byte, error) {
	return json.Marshal(path.String())
}

// UnmarshalJSON a json-serialized string back into a derivation path
// UnmarshalJSON 将 json 序列化字符串放回到派生路径中
func (path *DerivationPath) UnmarshalJSON(b []byte) error {
	var dp string
	var err error
	if err = json.Unmarshal(b, &dp); err != nil {
		return err
	}
	*path, err = ParseDerivationPath(dp)
	return err
}

// DefaultIterator creates a BIP-32 path iterator, which progresses by increasing the last component: i.e. m/44'/60'/0'/0/0, m/44'/60'/0'/0/1, m/44'/60'/0'/0/2, ... m/44'/60'/0'/0/N.
// DefaultIterator 创建一个 BIP-32 路径迭代器，它通过增加最后一个组件来进行：即 m/44'/60'/0'/0/0、m/44'/60'/0'/0/1、m/ 44'/60'/0'/0/2，...米/44'/60'/0'/0/N。
func DefaultIterator(base DerivationPath) func() DerivationPath {
	path := make(DerivationPath, len(base))
	copy(path[:], base[:])
	// Set it back by one, so the first call gives the first result
	// 将其设置回 1，因此第一次调用给出第一个结果
	path[len(path)-1]--
	return func() DerivationPath {
		path[len(path)-1]++
		return path
	}
}

// LedgerLiveIterator creates a bip44 path iterator for Ledger Live. Ledger Live increments the third component rather than the fifth component i.e. m/44'/60'/0'/0/0, m/44'/60'/1'/0/0, m/44'/60'/2'/0/0, ... m/44'/60'/N'/0/0.
// LedgerLiveIterator 为 Ledger Live 创建一个 bip44 路径迭代器。 Ledger Live 增加第三个分量而不是第五个分量，即 m/44'/60'/0'/0/0、m/44'/60'/1'/0/0、m/44'/60'/ 2'/0/0，...米/44'/60'/N'/0/0。
func LedgerLiveIterator(base DerivationPath) func() DerivationPath {
	path := make(DerivationPath, len(base))
	copy(path[:], base[:])
	// Set it back by one, so the first call gives the first result
	// 将其设置回 1，因此第一次调用给出第一个结果
	path[2]--
	return func() DerivationPath {
		// ledgerLivePathIterator iterates on the third component
		// ledgerLivePathIterator 迭代第三个组件
		path[2]++
		return path
	}
}


