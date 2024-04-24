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
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
)

// ConvertType converts an interface of a runtime type into a interface of the given type, e.g. turn this code:
// ConvertType 将运行时类型的接口转换为给定类型的接口，例如转此代码：
//	var fields []reflect.StructField
//	fields = append(fields, reflect.StructField{
//	fields = append(fields, reflect.StructField{
//	字段 = 追加（字段，reflect.StructField{
//			Name: "X",
//			名称：“X”，
//			Type: reflect.TypeOf(new(big.Int)),
//			类型：reflect.TypeOf(new(big.Int)),
//			Tag:  reflect.StructTag("json:\"" + "x" + "\""),
//			标签：reflect.StructTag("json:\"" + "x" + "\""),
//	}
// into:
// 进入：
//	type TupleT struct { X *big.Int }
//	类型 TupleT 结构 { X *big.Int }
func ConvertType(in interface{}, proto interface{}) interface{} {
	protoType := reflect.TypeOf(proto)
	if reflect.TypeOf(in).ConvertibleTo(protoType) {
		return reflect.ValueOf(in).Convert(protoType).Interface()
	}
	// Use set as a last ditch effort
	// 使用集合作为最后的努力
	if err := set(reflect.ValueOf(proto), reflect.ValueOf(in)); err != nil {
		panic(err)
	}
	return proto
}

// indirect recursively dereferences the value until it either gets the value or finds a big.Int
// 间接递归地取消引用该值，直到获取该值或找到一个 big.Int
func indirect(v reflect.Value) reflect.Value {
	if v.Kind() == reflect.Ptr && v.Elem().Type() != reflect.TypeOf(big.Int{}) {
		return indirect(v.Elem())
	}
	return v
}

// reflectIntType returns the reflect using the given size and unsignedness.
// ReflectIntType 使用给定的大小和无符号性返回反射。
func reflectIntType(unsigned bool, size int) reflect.Type {
	if unsigned {
		switch size {
		case 8:
			return reflect.TypeOf(uint8(0))
		case 16:
			return reflect.TypeOf(uint16(0))
		case 32:
			return reflect.TypeOf(uint32(0))
		case 64:
			return reflect.TypeOf(uint64(0))
		}
	}
	switch size {
	case 8:
		return reflect.TypeOf(int8(0))
	case 16:
		return reflect.TypeOf(int16(0))
	case 32:
		return reflect.TypeOf(int32(0))
	case 64:
		return reflect.TypeOf(int64(0))
	}
	return reflect.TypeOf(&big.Int{})
}

// mustArrayToByteSlice creates a new byte slice with the exact same size as value and copies the bytes in value to the new slice.
// MustArrayToByteSlice 创建一个与 value 大小完全相同的新字节切片，并将 value 中的字节复制到新切片。
func mustArrayToByteSlice(value reflect.Value) reflect.Value {
	slice := reflect.MakeSlice(reflect.TypeOf([]byte{}), value.Len(), value.Len())
	reflect.Copy(slice, value)
	return slice
}

// set attempts to assign src to dst by either setting, copying or otherwise.
// set 尝试通过设置、复制或其他方式将 src 分配给 dst。
// set is a bit more lenient when it comes to assignment and doesn't force an as strict ruleset as bare `reflect` does.
// set 在分配时稍微宽松一些，并且不会像裸露的“reflect”那样强制执行严格的规则集。
func set(dst, src reflect.Value) error {
	dstType, srcType := dst.Type(), src.Type()
	switch {
	case dstType.Kind() == reflect.Interface && dst.Elem().IsValid() && (dst.Elem().Type().Kind() == reflect.Ptr || dst.Elem().CanSet()):
		return set(dst.Elem(), src)
	case dstType.Kind() == reflect.Ptr && dstType.Elem() != reflect.TypeOf(big.Int{}):
		return set(dst.Elem(), src)
	case srcType.AssignableTo(dstType) && dst.CanSet():
		dst.Set(src)
	case dstType.Kind() == reflect.Slice && srcType.Kind() == reflect.Slice && dst.CanSet():
		return setSlice(dst, src)
	case dstType.Kind() == reflect.Array:
		return setArray(dst, src)
	case dstType.Kind() == reflect.Struct:
		return setStruct(dst, src)
	default:
		return fmt.Errorf("abi: cannot unmarshal %v in to %v", src.Type(), dst.Type())
	}
	return nil
}

// setSlice attempts to assign src to dst when slices are not assignable by default e.g. src: [][]byte -> dst: [][15]byte setSlice ignores if we cannot copy all of src' elements.
// 当切片默认不可分配时，setSlice 会尝试将 src 分配给 dst，例如src: [][]byte -> dst: [][15]byte 如果我们无法复制所有 src' 元素，setSlice 会忽略。
func setSlice(dst, src reflect.Value) error {
	slice := reflect.MakeSlice(dst.Type(), src.Len(), src.Len())
	for i := 0; i < src.Len(); i++ {
		if err := set(slice.Index(i), src.Index(i)); err != nil {
			return err
		}
	}
	if dst.CanSet() {
		dst.Set(slice)
		return nil
	}
	return errors.New("cannot set slice, destination not settable")
}

func setArray(dst, src reflect.Value) error {
	if src.Kind() == reflect.Ptr {
		return set(dst, indirect(src))
	}
	array := reflect.New(dst.Type()).Elem()
	min := src.Len()
	if src.Len() > dst.Len() {
		min = dst.Len()
	}
	for i := 0; i < min; i++ {
		if err := set(array.Index(i), src.Index(i)); err != nil {
			return err
		}
	}
	if dst.CanSet() {
		dst.Set(array)
		return nil
	}
	return errors.New("cannot set array, destination not settable")
}

func setStruct(dst, src reflect.Value) error {
	for i := 0; i < src.NumField(); i++ {
		srcField := src.Field(i)
		dstField := dst.Field(i)
		if !dstField.IsValid() || !srcField.IsValid() {
			return fmt.Errorf("could not find src field: %v value: %v in destination", srcField.Type().Name(), srcField)
		}
		if err := set(dstField, srcField); err != nil {
			return err
		}
	}
	return nil
}

// mapArgNamesToStructFields maps a slice of argument names to struct fields.
// mapArgNamesToStructFields 将参数名称切片映射到结构字段。
// first round: for each Exportable field that contains a `abi:""` tag and this field name exists in the given argument name list, pair them together.
// 第一轮：对于每个包含 `abi:""` 标签且该字段名称存在于给定参数名称列表中的可导出字段，将它们配对在一起。
// second round: for each argument name that has not been already linked, find what variable is expected to be mapped into, if it exists and has not been used, pair them.
// 第二轮：对于每个尚未链接的参数名称，找到期望映射到的变量，如果存在且尚未使用，则将它们配对。
// Note this function assumes the given value is a struct value.
// 请注意，此函数假定给定值是结构体值。
func mapArgNamesToStructFields(argNames []string, value reflect.Value) (map[string]string, error) {
	typ := value.Type()

	abi2struct := make(map[string]string)
	struct2abi := make(map[string]string)

	// first round ~~~
	// 第一轮~~~
	for i := 0; i < typ.NumField(); i++ {
		structFieldName := typ.Field(i).Name

		// skip private struct fields.
		// 跳过私有结构字段。
		if structFieldName[:1] != strings.ToUpper(structFieldName[:1]) {
			continue
		}
		// skip fields that have no abi:"" tag.
		// 跳过没有 abi:"" 标签的字段。
		tagName, ok := typ.Field(i).Tag.Lookup("abi")
		if !ok {
			continue
		}
		// check if tag is empty.
		// 检查标签是否为空。
		if tagName == "" {
			return nil, fmt.Errorf("struct: abi tag in '%s' is empty", structFieldName)
		}
		// check which argument field matches with the abi tag.
		// 检查哪个参数字段与 abi 标记匹配。
		found := false
		for _, arg := range argNames {
			if arg == tagName {
				if abi2struct[arg] != "" {
					return nil, fmt.Errorf("struct: abi tag in '%s' already mapped", structFieldName)
				}
				// pair them
				// 将他们配对
				abi2struct[arg] = structFieldName
				struct2abi[structFieldName] = arg
				found = true
			}
		}
		// check if this tag has been mapped.
		// 检查该标签是否已被映射。
		if !found {
			return nil, fmt.Errorf("struct: abi tag '%s' defined but not found in abi", tagName)
		}
	}

	// second round ~~~
	// 第二轮~~~
	for _, argName := range argNames {
		structFieldName := ToCamelCase(argName)

		if structFieldName == "" {
			return nil, errors.New("abi: purely underscored output cannot unpack to struct")
		}

		// this abi has already been paired, skip it... unless there exists another, yet unassigned struct field with the same field name. If so, raise an error:
		// 此 abi 已配对，跳过它...除非存在另一个具有相同字段名称但未分配的结构字段。如果是这样，请提出错误：
		//    abi: [ { "name": "value" } ]
		//    abi: [ { "名称": "值" } ]
		//    struct { Value  *big.Int , Value1 *big.Int `abi:"value"`}
		//    return an error if this struct field has already been paired.
		if abi2struct[argName] != "" {
			if abi2struct[argName] != structFieldName &&
				struct2abi[structFieldName] == "" &&
				value.FieldByName(structFieldName).IsValid() {
				return nil, fmt.Errorf("abi: multiple variables maps to the same abi field '%s'", argName)
			}
			continue
		}

		// return an error if this struct field has already been paired.
		// 如果该结构体字段已经配对，则返回错误。
		if struct2abi[structFieldName] != "" {
			return nil, fmt.Errorf("abi: multiple outputs mapping to the same struct field '%s'", structFieldName)
		}

		if value.FieldByName(structFieldName).IsValid() {
			// pair them
			// 将他们配对
			abi2struct[argName] = structFieldName
			struct2abi[structFieldName] = argName
		} else {
			// not paired, but annotate as used, to detect cases like
			// 不配对，但按使用情况进行注释，以检测类似的情况
			//   abi : [ { "name": "value" }, { "name": "_value" } ]
			//   struct { Value *big.Int }
			//   struct { Value *big.Int }
			//   结构体 { 值 *big.Int }
			struct2abi[structFieldName] = argName
		}
	}
	return abi2struct, nil
}


