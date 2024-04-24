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

package abi

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Argument holds the name of the argument and the corresponding type. Types are used when packing and testing arguments.
// Argument 保存参数的名称和相应的类型。打包和测试参数时使用类型。
type Argument struct {
	Name    string
	Type    Type
	Indexed bool // indexed is only used by events // 索引仅由事件使用
}

type Arguments []Argument

type ArgumentMarshaling struct {
	Name         string
	Type         string
	InternalType string
	Components   []ArgumentMarshaling
	Indexed      bool
}

// UnmarshalJSON implements json.Unmarshaler interface.
// UnmarshalJSON 实现 json.Unmarshaler 接口。
func (argument *Argument) UnmarshalJSON(data []byte) error {
	var arg ArgumentMarshaling
	err := json.Unmarshal(data, &arg)
	if err != nil {
		return fmt.Errorf("argument json err: %v", err)
	}

	argument.Type, err = NewType(arg.Type, arg.InternalType, arg.Components)
	if err != nil {
		return err
	}
	argument.Name = arg.Name
	argument.Indexed = arg.Indexed

	return nil
}

// NonIndexed returns the arguments with indexed arguments filtered out.
// NonIndexed 返回已过滤掉索引参数的参数。
func (arguments Arguments) NonIndexed() Arguments {
	var ret []Argument
	for _, arg := range arguments {
		if !arg.Indexed {
			ret = append(ret, arg)
		}
	}
	return ret
}

// isTuple returns true for non-atomic constructs, like (uint,uint) or uint[].
// isTuple 对于非原子构造返回 true，例如 (uint,uint) 或 uint[]。
func (arguments Arguments) isTuple() bool {
	return len(arguments) > 1
}

// Unpack performs the operation hexdata -> Go format.
// 解包执行操作 hexdata -> Go format。
func (arguments Arguments) Unpack(data []byte) ([]interface{}, error) {
	if len(data) == 0 {
		if len(arguments.NonIndexed()) != 0 {
			return nil, errors.New("abi: attempting to unmarshal an empty string while arguments are expected")
		}
		return make([]interface{}, 0), nil
	}
	return arguments.UnpackValues(data)
}

// UnpackIntoMap performs the operation hexdata -> mapping of argument name to argument value.
// UnpackIntoMap 执行操作 hexdata -> 将参数名称映射到参数值。
func (arguments Arguments) UnpackIntoMap(v map[string]interface{}, data []byte) error {
	// Make sure map is not nil
	// 确保地图不为零
	if v == nil {
		return errors.New("abi: cannot unpack into a nil map")
	}
	if len(data) == 0 {
		if len(arguments.NonIndexed()) != 0 {
			return errors.New("abi: attempting to unmarshal an empty string while arguments are expected")
		}
		return nil // Nothing to unmarshal, return // 没有什么需要解组的，返回
	}
	marshalledValues, err := arguments.UnpackValues(data)
	if err != nil {
		return err
	}
	for i, arg := range arguments.NonIndexed() {
		v[arg.Name] = marshalledValues[i]
	}
	return nil
}

// Copy performs the operation go format -> provided struct.
// Copy 执行操作 go format ->provided struct。
func (arguments Arguments) Copy(v interface{}, values []interface{}) error {
	// make sure the passed value is arguments pointer
	// 确保传递的值是参数指针
	if reflect.Ptr != reflect.ValueOf(v).Kind() {
		return fmt.Errorf("abi: Unpack(non-pointer %T)", v)
	}
	if len(values) == 0 {
		if len(arguments.NonIndexed()) != 0 {
			return errors.New("abi: attempting to copy no values while arguments are expected")
		}
		return nil // Nothing to copy, return // 没什么可复制的，返回
	}
	if arguments.isTuple() {
		return arguments.copyTuple(v, values)
	}
	return arguments.copyAtomic(v, values[0])
}

// copyAtomic copies ( hexdata -> go ) a single value
// copyAtomic 复制 ( hexdata -> go ) 单个值
func (arguments Arguments) copyAtomic(v interface{}, marshalledValues interface{}) error {
	dst := reflect.ValueOf(v).Elem()
	src := reflect.ValueOf(marshalledValues)

	if dst.Kind() == reflect.Struct {
		return set(dst.Field(0), src)
	}
	return set(dst, src)
}

// copyTuple copies a batch of values from marshalledValues to v.
// copyTuple 将一批值从 marshalledValues 复制到 v。
func (arguments Arguments) copyTuple(v interface{}, marshalledValues []interface{}) error {
	value := reflect.ValueOf(v).Elem()
	nonIndexedArgs := arguments.NonIndexed()

	switch value.Kind() {
	case reflect.Struct:
		argNames := make([]string, len(nonIndexedArgs))
		for i, arg := range nonIndexedArgs {
			argNames[i] = arg.Name
		}
		var err error
		abi2struct, err := mapArgNamesToStructFields(argNames, value)
		if err != nil {
			return err
		}
		for i, arg := range nonIndexedArgs {
			field := value.FieldByName(abi2struct[arg.Name])
			if !field.IsValid() {
				return fmt.Errorf("abi: field %s can't be found in the given value", arg.Name)
			}
			if err := set(field, reflect.ValueOf(marshalledValues[i])); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if value.Len() < len(marshalledValues) {
			return fmt.Errorf("abi: insufficient number of arguments for unpack, want %d, got %d", len(arguments), value.Len())
		}
		for i := range nonIndexedArgs {
			if err := set(value.Index(i), reflect.ValueOf(marshalledValues[i])); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("abi:[2] cannot unmarshal tuple in to %v", value.Type())
	}
	return nil
}

// UnpackValues can be used to unpack ABI-encoded hexdata according to the ABI-specification, without supplying a struct to unpack into. Instead, this method returns a list containing the values. An atomic argument will be a list with one element.
// UnpackValues 可用于根据 ABI 规范解包 ABI 编码的十六进制数据，而无需提供要解包的结构。相反，此方法返回包含值的列表。原子参数将是一个包含一个元素的列表。
func (arguments Arguments) UnpackValues(data []byte) ([]interface{}, error) {
	nonIndexedArgs := arguments.NonIndexed()
	retval := make([]interface{}, 0, len(nonIndexedArgs))
	virtualArgs := 0
	for index, arg := range nonIndexedArgs {
		marshalledValue, err := toGoType((index+virtualArgs)*32, arg.Type, data)
		if err != nil {
			return nil, err
		}
		if arg.Type.T == ArrayTy && !isDynamicType(arg.Type) {
			// If we have a static array, like [3]uint256, these are coded as just like uint256,uint256,uint256. This means that we need to add two 'virtual' arguments when we count the index from now on.
			// 如果我们有一个静态数组，例如 [3]uint256，它们的编码就像 uint256、uint256、uint256 一样。这意味着从现在开始计算索引时我们需要添加两个“虚拟”参数。
			// Array values nested multiple levels deep are also encoded inline: [2][3]uint256: uint256,uint256,uint256,uint256,uint256,uint256
			// 嵌套多级深度的数组值也被内联编码： [2][3]uint256: uint256,uint256,uint256,uint256,uint256,uint256
			// Calculate the full array size to get the correct offset for the next argument. Decrement it by 1, as the normal index increment is still applied.
			// 计算完整数组大小以获得下一个参数的正确偏移量。将其减 1，因为仍应用正常索引增量。
			virtualArgs += getTypeSize(arg.Type)/32 - 1
		} else if arg.Type.T == TupleTy && !isDynamicType(arg.Type) {
			// If we have a static tuple, like (uint256, bool, uint256), these are coded as just like uint256,bool,uint256
			// 如果我们有一个静态元组，例如 (uint256, bool, uint256)，它们的编码就像 uint256,bool,uint256
			virtualArgs += getTypeSize(arg.Type)/32 - 1
		}
		retval = append(retval, marshalledValue)
	}
	return retval, nil
}

// PackValues performs the operation Go format -> Hexdata. It is the semantic opposite of UnpackValues.
// PackValues 执行操作 Go format -> Hexdata。它与 UnpackValues 的语义相反。
func (arguments Arguments) PackValues(args []interface{}) ([]byte, error) {
	return arguments.Pack(args...)
}

// Pack performs the operation Go format -> Hexdata.
// Pack 执行操作 Go format -> Hexdata。
func (arguments Arguments) Pack(args ...interface{}) ([]byte, error) {
	// Make sure arguments match up and pack them
	// 确保参数匹配并打包它们
	abiArgs := arguments
	if len(args) != len(abiArgs) {
		return nil, fmt.Errorf("argument count mismatch: got %d for %d", len(args), len(abiArgs))
	}
	// variable input is the output appended at the end of packed output. This is used for strings and bytes types input.
	// 变量输入是附加在打包输出末尾的输出。这用于字符串和字节类型输入。
	var variableInput []byte

	// input offset is the bytes offset for packed output
	// 输入偏移量是打包输出的字节偏移量
	inputOffset := 0
	for _, abiArg := range abiArgs {
		inputOffset += getTypeSize(abiArg.Type)
	}
	var ret []byte
	for i, a := range args {
		input := abiArgs[i]
		// pack the input
		// 打包输入
		packed, err := input.Type.pack(reflect.ValueOf(a))
		if err != nil {
			return nil, err
		}
		// check for dynamic types
		// 检查动态类型
		if isDynamicType(input.Type) {
			// set the offset
			// 设置偏移量
			ret = append(ret, packNum(reflect.ValueOf(inputOffset))...)
			// calculate next offset
			// 计算下一个偏移量
			inputOffset += len(packed)
			// append to variable input
			// 附加到变量输入
			variableInput = append(variableInput, packed...)
		} else {
			// append the packed value to the input
			// 将打包值附加到输入
			ret = append(ret, packed...)
		}
	}
	// append the variable input at the end of the packed input
	// 将变量输入附加到打包输入的末尾
	ret = append(ret, variableInput...)

	return ret, nil
}

// ToCamelCase converts an under-score string to a camel-case string
// ToCamelCase 将下划线字符串转换为驼峰式字符串
func ToCamelCase(input string) string {
	parts := strings.Split(input, "_")
	for i, s := range parts {
		if len(s) > 0 {
			parts[i] = strings.ToUpper(s[:1]) + s[1:]
		}
	}
	return strings.Join(parts, "")
}


