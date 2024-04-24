// Copyright 2022 The go-ethereum Authors
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

package abi

import "fmt"

// ResolveNameConflict returns the next available name for a given thing. This helper can be used for lots of purposes:
// ResolveNameConflict 返回给定事物的下一个可用名称。这个助手有很多用途：
//   - In solidity function overloading is supported, this function can fix
//   - 在solidity中支持函数重载，该函数可以修复
//     the name conflicts of overloaded functions.
//     重载函数的名称冲突。
//   - In golang binding generation, the parameter(in function, event, error,
//   - 在golang绑定生成中，参数（在函数、事件、错误中，
//     and struct definition) name will be converted to camelcase style which
//     和结构定义）名称将转换为驼峰风格
//     may eventually lead to name conflicts.
//     最终可能会导致名称冲突。
// Name conflicts are mostly resolved by adding number suffix. e.g. if the abi contains Methods "send" and "send1", ResolveNameConflict would return "send2" for input "send".
// 名称冲突大多通过添加数字后缀来解决。例如如果 abi 包含方法“send”和“send1”，ResolveNameConflict 将为输入“send”返回“send2”。
func ResolveNameConflict(rawName string, used func(string) bool) string {
	name := rawName
	ok := used(name)
	for idx := 0; ok; idx++ {
		name = fmt.Sprintf("%s%d", rawName, idx)
		ok = used(name)
	}
	return name
}


