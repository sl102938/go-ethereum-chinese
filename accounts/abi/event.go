// Copyright 2016 The go-ethereum Authors
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

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Event is an event potentially triggered by the EVM's LOG mechanism. The Event holds type information (inputs) about the yielded output. Anonymous events don't get the signature canonical representation as the first LOG topic.
// 事件是可能由EVM的LOG机制触发的事件。事件保存有关产生的输出的类型信息（输入）。匿名事件不会将签名规范表示作为第一个 LOG 主题。
type Event struct {
	// Name is the event name used for internal representation. It's derived from the raw name and a suffix will be added in the case of event overloading.
	// 名称是用于内部表示的事件名称。它源自原始名称，并且在事件重载的情况下将添加后缀。
	// e.g. These are two events that have the same name: * foo(int,int) * foo(uint,uint) The event name of the first one will be resolved as foo while the second one will be resolved as foo0.
	// 例如这是两个具有相同名称的事件： * foo(int,int) * foo(uint,uint) 第一个事件名称将解析为 foo，而第二个事件名称将解析为 foo0。
	Name string

	// RawName is the raw event name parsed from ABI.
	// RawName 是从 ABI 解析的原始事件名称。
	RawName   string
	Anonymous bool
	Inputs    Arguments
	str       string

	// Sig contains the string signature according to the ABI spec. e.g.	 event foo(uint32 a, int b) = "foo(uint32,int256)" Please note that "int" is substitute for its canonical representation "int256"
	// Sig 包含根据 ABI 规范的字符串签名。例如event foo(uint32 a, int b) = "foo(uint32,int256)" 请注意，“int”替代了其规范表示“int256”
	Sig string

	// ID returns the canonical representation of the event's signature used by the abi definition to identify event names and types.
	// ID 返回事件签名的规范表示，abi 定义使用该签名来标识事件名称和类型。
	ID common.Hash
}

// NewEvent creates a new Event. It sanitizes the input arguments to remove unnamed arguments. It also precomputes the id, signature and string representation of the event.
// NewEvent 创建一个新事件。它清理输入参数以删除未命名的参数。它还预先计算事件的 ID、签名和字符串表示形式。
func NewEvent(name, rawName string, anonymous bool, inputs Arguments) Event {
	// sanitize inputs to remove inputs without names and precompute string and sig representation.
	// 清理输入以删除没有名称的输入并预先计算字符串和 sig 表​​示形式。
	names := make([]string, len(inputs))
	types := make([]string, len(inputs))
	for i, input := range inputs {
		if input.Name == "" {
			inputs[i] = Argument{
				Name:    fmt.Sprintf("arg%d", i),
				Indexed: input.Indexed,
				Type:    input.Type,
			}
		} else {
			inputs[i] = input
		}
		// string representation
		// 字符串表示
		names[i] = fmt.Sprintf("%v %v", input.Type, inputs[i].Name)
		if input.Indexed {
			names[i] = fmt.Sprintf("%v indexed %v", input.Type, inputs[i].Name)
		}
		// sig representation
		// 信号表示
		types[i] = input.Type.String()
	}

	str := fmt.Sprintf("event %v(%v)", rawName, strings.Join(names, ", "))
	sig := fmt.Sprintf("%v(%v)", rawName, strings.Join(types, ","))
	id := common.BytesToHash(crypto.Keccak256([]byte(sig)))

	return Event{
		Name:      name,
		RawName:   rawName,
		Anonymous: anonymous,
		Inputs:    inputs,
		str:       str,
		Sig:       sig,
		ID:        id,
	}
}

func (e Event) String() string {
	return e.str
}


