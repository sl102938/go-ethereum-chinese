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
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
)

// Type enumerator
// 类型枚举器
const (
	IntTy byte = iota
	UintTy
	BoolTy
	StringTy
	SliceTy
	ArrayTy
	TupleTy
	AddressTy
	FixedBytesTy
	BytesTy
	HashTy
	FixedPointTy
	FunctionTy
)

// Type is the reflection of the supported argument type.
// 类型是支持的参数类型的反映。
type Type struct {
	Elem *Type
	Size int
	T    byte // Our own type checking // 我们自己的类型检查

	stringKind string // holds the unparsed string for deriving signatures // 保存用于派生签名的未解析字符串

	// Tuple relative fields
	// 元组相关字段
	TupleRawName  string       // Raw struct name defined in source code, may be empty. // 源代码中定义的原始结构名称可能为空。
	TupleElems    []*Type      // Type information of all tuple fields // 所有元组字段的类型信息
	TupleRawNames []string     // Raw field name of all tuple fields // 所有元组字段的原始字段名称
	TupleType     reflect.Type // Underlying struct of the tuple // 元组的底层结构
}

var (
	// typeRegex parses the abi sub types
	// typeRegex 解析 abi 子类型
	typeRegex = regexp.MustCompile("([a-zA-Z]+)(([0-9]+)(x([0-9]+))?)?")
)

// NewType creates a new reflection type of abi type given in t.
// NewType 创建 t 中给定的 abi 类型的新反射类型。
func NewType(t string, internalType string, components []ArgumentMarshaling) (typ Type, err error) {
	// check that array brackets are equal if they exist
	// 检查数组括号是否相等（如果存在）
	if strings.Count(t, "[") != strings.Count(t, "]") {
		return Type{}, errors.New("invalid arg type in abi")
	}
	typ.stringKind = t

	// if there are brackets, get ready to go into slice/array mode and recursively create the type
	// 如果有括号，准备进入切片/数组模式并递归创建类型
	if strings.Count(t, "[") != 0 {
		// Note internalType can be empty here.
		// 注意此处的internalType 可以为空。
		subInternal := internalType
		if i := strings.LastIndex(internalType, "["); i != -1 {
			subInternal = subInternal[:i]
		}
		// recursively embed the type
		// 递归嵌入类型
		i := strings.LastIndex(t, "[")
		embeddedType, err := NewType(t[:i], subInternal, components)
		if err != nil {
			return Type{}, err
		}
		// grab the last cell and create a type from there
		// 抓住最后一个单元格并从那里创建一个类型
		sliced := t[i:]
		// grab the slice size with regexp
		// 使用正则表达式获取切片大小
		re := regexp.MustCompile("[0-9]+")
		intz := re.FindAllString(sliced, -1)

		if len(intz) == 0 {
			// is a slice
			// 是一个切片
			typ.T = SliceTy
			typ.Elem = &embeddedType
			typ.stringKind = embeddedType.stringKind + sliced
		} else if len(intz) == 1 {
			// is an array
			// 是一个数组
			typ.T = ArrayTy
			typ.Elem = &embeddedType
			typ.Size, err = strconv.Atoi(intz[0])
			if err != nil {
				return Type{}, fmt.Errorf("abi: error parsing variable size: %v", err)
			}
			typ.stringKind = embeddedType.stringKind + sliced
		} else {
			return Type{}, errors.New("invalid formatting of array type")
		}
		return typ, err
	}
	// parse the type and size of the abi-type.
	// 解析 abi 类型的类型和大小。
	matches := typeRegex.FindAllStringSubmatch(t, -1)
	if len(matches) == 0 {
		return Type{}, fmt.Errorf("invalid type '%v'", t)
	}
	parsedType := matches[0]

	// varSize is the size of the variable
	// varSize 是变量的大小
	var varSize int
	if len(parsedType[3]) > 0 {
		var err error
		varSize, err = strconv.Atoi(parsedType[2])
		if err != nil {
			return Type{}, fmt.Errorf("abi: error parsing variable size: %v", err)
		}
	} else {
		if parsedType[0] == "uint" || parsedType[0] == "int" {
			// this should fail because it means that there's something wrong with the abi type (the compiler should always format it to the size...always)
			// 这应该会失败，因为这意味着 abi 类型有问题（编译器应该始终将其格式化为大小......始终）
			return Type{}, fmt.Errorf("unsupported arg type: %s", t)
		}
	}
	// varType is the parsed abi type
	// varType 是解析后的 abi 类型
	switch varType := parsedType[1]; varType {
	case "int":
		typ.Size = varSize
		typ.T = IntTy
	case "uint":
		typ.Size = varSize
		typ.T = UintTy
	case "bool":
		typ.T = BoolTy
	case "address":
		typ.Size = 20
		typ.T = AddressTy
	case "string":
		typ.T = StringTy
	case "bytes":
		if varSize == 0 {
			typ.T = BytesTy
		} else {
			if varSize > 32 {
				return Type{}, fmt.Errorf("unsupported arg type: %s", t)
			}
			typ.T = FixedBytesTy
			typ.Size = varSize
		}
	case "tuple":
		var (
			fields     []reflect.StructField
			elems      []*Type
			names      []string
			expression string // canonical parameter expression // 规范参数表达式
			used       = make(map[string]bool)
		)
		expression += "("
		for idx, c := range components {
			cType, err := NewType(c.Type, c.InternalType, c.Components)
			if err != nil {
				return Type{}, err
			}
			name := ToCamelCase(c.Name)
			if name == "" {
				return Type{}, errors.New("abi: purely anonymous or underscored field is not supported")
			}
			fieldName := ResolveNameConflict(name, func(s string) bool { return used[s] })
			used[fieldName] = true
			if !isValidFieldName(fieldName) {
				return Type{}, fmt.Errorf("field %d has invalid name", idx)
			}
			fields = append(fields, reflect.StructField{
				Name: fieldName, // reflect.StructOf will panic for any exported field. // Reflect.StructOf 会对任何导出的字段感到恐慌。
				Type: cType.GetType(),
				Tag:  reflect.StructTag("json:\"" + c.Name + "\""),
			})
			elems = append(elems, &cType)
			names = append(names, c.Name)
			expression += cType.stringKind
			if idx != len(components)-1 {
				expression += ","
			}
		}
		expression += ")"

		typ.TupleType = reflect.StructOf(fields)
		typ.TupleElems = elems
		typ.TupleRawNames = names
		typ.T = TupleTy
		typ.stringKind = expression

		const structPrefix = "struct "
		// After solidity 0.5.10, a new field of abi "internalType" is introduced. From that we can obtain the struct name user defined in the source code.
		// 在solidity 0.5.10之后，引入了abi的新字段“internalType”。由此我们可以获取源代码中定义的结构体名称user。
		if internalType != "" && strings.HasPrefix(internalType, structPrefix) {
			// Foo.Bar type definition is not allowed in golang, convert the format to FooBar
			// golang中不允许Foo.Bar类型定义，将格式转换为FooBar
			typ.TupleRawName = strings.ReplaceAll(internalType[len(structPrefix):], ".", "")
		}

	case "function":
		typ.T = FunctionTy
		typ.Size = 24
	default:
		return Type{}, fmt.Errorf("unsupported arg type: %s", t)
	}

	return
}

// GetType returns the reflection type of the ABI type.
// GetType 返回 ABI 类型的反射类型。
func (t Type) GetType() reflect.Type {
	switch t.T {
	case IntTy:
		return reflectIntType(false, t.Size)
	case UintTy:
		return reflectIntType(true, t.Size)
	case BoolTy:
		return reflect.TypeOf(false)
	case StringTy:
		return reflect.TypeOf("")
	case SliceTy:
		return reflect.SliceOf(t.Elem.GetType())
	case ArrayTy:
		return reflect.ArrayOf(t.Size, t.Elem.GetType())
	case TupleTy:
		return t.TupleType
	case AddressTy:
		return reflect.TypeOf(common.Address{})
	case FixedBytesTy:
		return reflect.ArrayOf(t.Size, reflect.TypeOf(byte(0)))
	case BytesTy:
		return reflect.SliceOf(reflect.TypeOf(byte(0)))
	case HashTy:
		// hashtype currently not used
		// 当前未使用的 hashtype
		return reflect.ArrayOf(32, reflect.TypeOf(byte(0)))
	case FixedPointTy:
		// fixedpoint type currently not used
		// 当前未使用的定点类型
		return reflect.ArrayOf(32, reflect.TypeOf(byte(0)))
	case FunctionTy:
		return reflect.ArrayOf(24, reflect.TypeOf(byte(0)))
	default:
		panic("Invalid type")
	}
}

// String implements Stringer.
// String 实现了 Stringer。
func (t Type) String() (out string) {
	return t.stringKind
}

func (t Type) pack(v reflect.Value) ([]byte, error) {
	// dereference pointer first if it's a pointer
	// 如果它是指针，则首先取消引用指针
	v = indirect(v)
	if err := typeCheck(t, v); err != nil {
		return nil, err
	}

	switch t.T {
	case SliceTy, ArrayTy:
		var ret []byte

		if t.requiresLengthPrefix() {
			// append length
			// 附加长度
			ret = append(ret, packNum(reflect.ValueOf(v.Len()))...)
		}

		// calculate offset if any
		// 计算偏移量（如果有）
		offset := 0
		offsetReq := isDynamicType(*t.Elem)
		if offsetReq {
			offset = getTypeSize(*t.Elem) * v.Len()
		}
		var tail []byte
		for i := 0; i < v.Len(); i++ {
			val, err := t.Elem.pack(v.Index(i))
			if err != nil {
				return nil, err
			}
			if !offsetReq {
				ret = append(ret, val...)
				continue
			}
			ret = append(ret, packNum(reflect.ValueOf(offset))...)
			offset += len(val)
			tail = append(tail, val...)
		}
		return append(ret, tail...), nil
	case TupleTy:
		// (T1,...,Tk) for k >= 0 and any types T1, …, Tk enc(X) = head(X(1)) ... head(X(k)) tail(X(1)) ... tail(X(k)) where X = (X(1), ..., X(k)) and head and tail are defined for Ti being a static type as
		// (T1,...,Tk) 对于 k >= 0 和任何类型 T1, ..., Tk enc(X) = head(X(1)) ... head(X(k)) tail(X(1) ) ... tail(X(k)) 其中 X = (X(1), ..., X(k)) 且 head 和 tail 被定义为 Ti 作为静态类型
		//     head(X(i)) = enc(X(i)) and tail(X(i)) = "" (the empty string)
		//     head(X(i)) = enc(X(i)) 和 tail(X(i)) = "" （空字符串）
		// and as
		// 并作为
		//     head(X(i)) = enc(len(head(X(1)) ... head(X(k)) tail(X(1)) ... tail(X(i-1))))
		//     头(X(i)) = enc(len(头(X(1)) ... 头(X(k)) 尾(X(1)) ... 尾(X(i-1))))
		//     tail(X(i)) = enc(X(i))
		//     尾部（X（i））= enc（X（i））
		// otherwise, i.e. if Ti is a dynamic type.
		// 否则，即如果 Ti 是动态类型。
		fieldmap, err := mapArgNamesToStructFields(t.TupleRawNames, v)
		if err != nil {
			return nil, err
		}
		// Calculate prefix occupied size.
		// 计算前缀占用的大小。
		offset := 0
		for _, elem := range t.TupleElems {
			offset += getTypeSize(*elem)
		}
		var ret, tail []byte
		for i, elem := range t.TupleElems {
			field := v.FieldByName(fieldmap[t.TupleRawNames[i]])
			if !field.IsValid() {
				return nil, fmt.Errorf("field %s for tuple not found in the given struct", t.TupleRawNames[i])
			}
			val, err := elem.pack(field)
			if err != nil {
				return nil, err
			}
			if isDynamicType(*elem) {
				ret = append(ret, packNum(reflect.ValueOf(offset))...)
				tail = append(tail, val...)
				offset += len(val)
			} else {
				ret = append(ret, val...)
			}
		}
		return append(ret, tail...), nil

	default:
		return packElement(t, v)
	}
}

// requiresLengthPrefix returns whether the type requires any sort of length prefixing.
// requireLengthPrefix 返回该类型是否需要任何类型的长度前缀。
func (t Type) requiresLengthPrefix() bool {
	return t.T == StringTy || t.T == BytesTy || t.T == SliceTy
}

// isDynamicType returns true if the type is dynamic. The following types are called “dynamic”: * bytes * string * T[] for any T * T[k] for any dynamic T and any k >= 0 * (T1,...,Tk) if Ti is dynamic for some 1 <= i <= k
// 如果类型是动态的，isDynamicType 返回 true。以下类型称为“动态”： * bytes * string * T[] 对于任何 T * T[k] 对于任何动态 T 和任何 k >= 0 * (T1,...,Tk) 如果 Ti 是动态的一些 1 `<`= i `<`= k
func isDynamicType(t Type) bool {
	if t.T == TupleTy {
		for _, elem := range t.TupleElems {
			if isDynamicType(*elem) {
				return true
			}
		}
		return false
	}
	return t.T == StringTy || t.T == BytesTy || t.T == SliceTy || (t.T == ArrayTy && isDynamicType(*t.Elem))
}

// getTypeSize returns the size that this type needs to occupy. We distinguish static and dynamic types. Static types are encoded in-place and dynamic types are encoded at a separately allocated location after the current block. So for a static variable, the size returned represents the size that the variable actually occupies. For a dynamic variable, the returned size is fixed 32 bytes, which is used to store the location reference for actual value storage.
// getTypeSize 返回该类型需要占用的大小。我们区分静态类型和动态类型。静态类型就地编码，动态类型在当前块之后单独分配的位置编码。所以对于静态变量来说，返回的大小代表的是该变量实际占用的大小。对于动态变量，返回的大小固定为32字节，用于存储实际值存储的位置引用。
func getTypeSize(t Type) int {
	if t.T == ArrayTy && !isDynamicType(*t.Elem) {
		// Recursively calculate type size if it is a nested array
		// 如果是嵌套数组，则递归计算类型大小
		if t.Elem.T == ArrayTy || t.Elem.T == TupleTy {
			return t.Size * getTypeSize(*t.Elem)
		}
		return t.Size * 32
	} else if t.T == TupleTy && !isDynamicType(t) {
		total := 0
		for _, elem := range t.TupleElems {
			total += getTypeSize(*elem)
		}
		return total
	}
	return 32
}

// isLetter reports whether a given 'rune' is classified as a Letter. This method is copied from reflect/type.go
// isLetter 报告给定的“符文”是否被分类为字母。该方法复制自reflect/type.go
func isLetter(ch rune) bool {
	return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || ch == '_' || ch >= utf8.RuneSelf && unicode.IsLetter(ch)
}

// isValidFieldName checks if a string is a valid (struct) field name or not.
// isValidFieldName 检查字符串是否是有效的（结构）字段名称。
// According to the language spec, a field name should be an identifier.
// 根据语言规范，字段名称应该是标识符。
// identifier = letter { letter | unicode_digit } . letter = unicode_letter | "_" . This method is copied from reflect/type.go
// 标识符 = 字母 { 字母 | unicode_digit } 。字母 = unicode_letter | “_”。该方法复制自reflect/type.go
func isValidFieldName(fieldName string) bool {
	for i, c := range fieldName {
		if i == 0 && !isLetter(c) {
			return false
		}

		if !(isLetter(c) || unicode.IsDigit(c)) {
			return false
		}
	}

	return len(fieldName) > 0
}


