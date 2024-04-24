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
	"fmt"
	"reflect"
	"testing"
)

// Tests that HD derivation paths can be correctly parsed into our internal binary representation.
// 测试 HD 派生路径是否可以正确解析为我们的内部二进制表示形式。
func TestHDPathParsing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input  string
		output DerivationPath
	}{
		// Plain absolute derivation paths
		// 简单的绝对推导路径
		{"m/44'/60'/0'/0", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0}},
		{"m/44'/60'/0'/128", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 128}},
		{"m/44'/60'/0'/0'", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0x80000000 + 0}},
		{"m/44'/60'/0'/128'", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0x80000000 + 128}},
		{"m/2147483692/2147483708/2147483648/0", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0}},
		{"m/2147483692/2147483708/2147483648/2147483648", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0x80000000 + 0}},

		// Plain relative derivation paths
		// 简单的相对推导路径
		{"0", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0}},
		{"128", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 128}},
		{"0'", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0x80000000 + 0}},
		{"128'", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0x80000000 + 128}},
		{"2147483648", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0x80000000 + 0}},

		// Hexadecimal absolute derivation paths
		// 十六进制绝对推导路径
		{"m/0x2C'/0x3c'/0x00'/0x00", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0}},
		{"m/0x2C'/0x3c'/0x00'/0x80", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 128}},
		{"m/0x2C'/0x3c'/0x00'/0x00'", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0x80000000 + 0}},
		{"m/0x2C'/0x3c'/0x00'/0x80'", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0x80000000 + 128}},
		{"m/0x8000002C/0x8000003c/0x80000000/0x00", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0}},
		{"m/0x8000002C/0x8000003c/0x80000000/0x80000000", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0x80000000 + 0}},

		// Hexadecimal relative derivation paths
		// 十六进制相对推导路径
		{"0x00", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0}},
		{"0x80", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 128}},
		{"0x00'", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0x80000000 + 0}},
		{"0x80'", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0x80000000 + 128}},
		{"0x80000000", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0x80000000 + 0}},

		// Weird inputs just to ensure they work
		// 奇怪的输入只是为了确保它们有效
		{"	m  /   44			'\n/\n   60	\n\n\t'   /\n0 ' /\t\t	0", DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0}},

		// Invalid derivation paths
		// 无效的派生路径
		{"", nil},              // Empty relative derivation path // 空相对导出路径
		{"m", nil},             // Empty absolute derivation path // 空绝对派生路径
		{"m/", nil},            // Missing last derivation component // 缺少最后一个推导组件
		{"/44'/60'/0'/0", nil}, // Absolute path without m prefix, might be user error // 没有 m 前缀的绝对路径，可能是用户错误
		{"m/2147483648'", nil}, // Overflows 32 bit integer // 32 位整数溢出
		{"m/-1'", nil},         // Cannot contain negative number // 不能包含负数
	}
	for i, tt := range tests {
		if path, err := ParseDerivationPath(tt.input); !reflect.DeepEqual(path, tt.output) {
			t.Errorf("test %d: parse mismatch: have %v (%v), want %v", i, path, err, tt.output)
		} else if path == nil && err == nil {
			t.Errorf("test %d: nil path and error: %v", i, err)
		}
	}
}

func testDerive(t *testing.T, next func() DerivationPath, expected []string) {
	t.Helper()
	for i, want := range expected {
		if have := next(); fmt.Sprintf("%v", have) != want {
			t.Errorf("step %d, have %v, want %v", i, have, want)
		}
	}
}

func TestHdPathIteration(t *testing.T) {
	t.Parallel()
	testDerive(t, DefaultIterator(DefaultBaseDerivationPath),
		[]string{
			"m/44'/60'/0'/0/0", "m/44'/60'/0'/0/1",
			"m/44'/60'/0'/0/2", "m/44'/60'/0'/0/3",
			"m/44'/60'/0'/0/4", "m/44'/60'/0'/0/5",
			"m/44'/60'/0'/0/6", "m/44'/60'/0'/0/7",
			"m/44'/60'/0'/0/8", "m/44'/60'/0'/0/9",
		})

	testDerive(t, DefaultIterator(LegacyLedgerBaseDerivationPath),
		[]string{
			"m/44'/60'/0'/0", "m/44'/60'/0'/1",
			"m/44'/60'/0'/2", "m/44'/60'/0'/3",
			"m/44'/60'/0'/4", "m/44'/60'/0'/5",
			"m/44'/60'/0'/6", "m/44'/60'/0'/7",
			"m/44'/60'/0'/8", "m/44'/60'/0'/9",
		})

	testDerive(t, LedgerLiveIterator(DefaultBaseDerivationPath),
		[]string{
			"m/44'/60'/0'/0/0", "m/44'/60'/1'/0/0",
			"m/44'/60'/2'/0/0", "m/44'/60'/3'/0/0",
			"m/44'/60'/4'/0/0", "m/44'/60'/5'/0/0",
			"m/44'/60'/6'/0/0", "m/44'/60'/7'/0/0",
			"m/44'/60'/8'/0/0", "m/44'/60'/9'/0/0",
		})
}


