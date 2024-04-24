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

package bind

import "github.com/ethereum/go-ethereum/accounts/abi"

// tmplData is the data structure required to fill the binding template.
// tmplData 是填充绑定模板所需的数据结构。
type tmplData struct {
	Package   string                   // Name of the package to place the generated file in // 放置生成文件的包的名称
	Contracts map[string]*tmplContract // List of contracts to generate into this file // 要生成到此文件中的合同列表
	Libraries map[string]string        // Map the bytecode's link pattern to the library name // 将字节码的链接模式映射到库名称
	Structs   map[string]*tmplStruct   // Contract struct type definitions // 合约结构类型定义
}

// tmplContract contains the data needed to generate an individual contract binding.
// tmplContract 包含生成单个合同绑定所需的数据。
type tmplContract struct {
	Type        string                 // Type name of the main contract binding // 主合同绑定的类型名称
	InputABI    string                 // JSON ABI used as the input to generate the binding from // JSON ABI 用作生成绑定的输入
	InputBin    string                 // Optional EVM bytecode used to generate deploy code from // 用于生成部署代码的可选 EVM 字节码
	FuncSigs    map[string]string      // Optional map: string signature -> 4-byte signature // 可选映射：字符串签名->4字节签名
	Constructor abi.Method             // Contract constructor for deploy parametrization // 用于部署参数化的合约构造函数
	Calls       map[string]*tmplMethod // Contract calls that only read state data // 仅读取状态数据的合约调用
	Transacts   map[string]*tmplMethod // Contract calls that write state data // 写入状态数据的合约调用
	Fallback    *tmplMethod            // Additional special fallback function // 附加特殊后备功能
	Receive     *tmplMethod            // Additional special receive function // 附加特殊接收功能
	Events      map[string]*tmplEvent  // Contract events accessors // 合约事件访问器
	Libraries   map[string]string      // Same as tmplData, but filtered to only keep what the contract needs // 与 tmplData 相同，但经过过滤以仅保留合约所需的内容
	Library     bool                   // Indicator whether the contract is a library // 指示合约是否是一个库
}

// tmplMethod is a wrapper around an abi.Method that contains a few preprocessed and cached data fields.
// tmplMethod 是 abi.Method 的包装器，其中包含一些预处理和缓存的数据字段。
type tmplMethod struct {
	Original   abi.Method // Original method as parsed by the abi package // abi 包解析的原始方法
	Normalized abi.Method // Normalized version of the parsed method (capitalized names, non-anonymous args/returns) // 已解析方法的规范化版本（大写名称、非匿名参数/返回）
	Structured bool       // Whether the returns should be accumulated into a struct // 返回值是否应该累积到一个结构体中
}

// tmplEvent is a wrapper around an abi.Event that contains a few preprocessed and cached data fields.
// tmplEvent 是 abi.Event 的包装器，其中包含一些预处理和缓存的数据字段。
type tmplEvent struct {
	Original   abi.Event // Original event as parsed by the abi package // 由 abi 包解析的原始事件
	Normalized abi.Event // Normalized version of the parsed fields // 已解析字段的规范化版本
}

// tmplField is a wrapper around a struct field with binding language struct type definition and relative filed name.
// tmplField 是一个结构字段的包装器，具有绑定语言结构类型定义和相对文件名。
type tmplField struct {
	Type    string   // Field type representation depends on target binding language // 字段类型表示取决于目标绑定语言
	Name    string   // Field name converted from the raw user-defined field name // 从原始用户定义字段名称转换而来的字段名称
	SolKind abi.Type // Raw abi type information // 原始 abi 类型信息
}

// tmplStruct is a wrapper around an abi.tuple and contains an auto-generated struct name.
// tmplStruct 是 abi.tuple 的包装器，包含自动生成的结构名称。
type tmplStruct struct {
	Name   string       // Auto-generated struct name(before solidity v0.5.11) or raw name. // 自动生成的结构名称（在 Solidity v0.5.11 之前）或原始名称。
	Fields []*tmplField // Struct fields definition depends on the binding language. // 结构字段定义取决于绑定语言。
}

// tmplSource is language to template mapping containing all the supported programming languages the package can generate to.
// tmplSource 是语言到模板的映射，包含包可以生成的所有受支持的编程语言。
var tmplSource = map[Lang]string{
	LangGo: tmplSourceGo,
}

// tmplSourceGo is the Go source template that the generated Go contract binding is based on.
// tmplSourceGo 是生成的 Go 合约绑定所基于的 Go 源模板。
const tmplSourceGo = `
// Code generated - DO NOT EDIT. This file is a generated binding and any manual changes will be lost.
// 生成的代码 - 请勿编辑。该文件是生成的绑定，任何手动更改都将丢失。

package {{.Package}}

import (
	"math/big"
	"strings"
	"errors"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
// 引用导入以抑制错误（如果不以其他方式使用它们）。
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

{{$structs := .Structs}}
{{range $structs}}
	// {{.Name}} is an auto generated low-level Go binding around an user-defined struct.
	// {{.Name}} 是围绕用户定义的结构自动生成的低级 Go 绑定。
	type {{.Name}} struct {
	{{range $field := .Fields}}
	{{$field.Name}} {{$field.Type}}{{end}}
	}
{{end}}

{{range $contract := .Contracts}}
	// {{.Type}}MetaData contains all meta data concerning the {{.Type}} contract.
	// {{.Type}}MetaData 包含有关 {{.Type}} 合约的所有元数据。
	var {{.Type}}MetaData = &bind.MetaData{
		ABI: "{{.InputABI}}",
		{{if $contract.FuncSigs -}}
		Sigs: map[string]string{
			{{range $strsig, $binsig := .FuncSigs}}"{{$binsig}}": "{{$strsig}}",
			{{end}}
		},
		{{end -}}
		{{if .InputBin -}}
		Bin: "0x{{.InputBin}}",
		{{end}}
	}
	// {{.Type}}ABI is the input ABI used to generate the binding from. Deprecated: Use {{.Type}}MetaData.ABI instead.
	// {{.Type}}ABI 是用于生成绑定的输入 ABI。已弃用：使用 {{.Type}}MetaData.ABI 代替。
	var {{.Type}}ABI = {{.Type}}MetaData.ABI

	{{if $contract.FuncSigs}}
		// Deprecated: Use {{.Type}}MetaData.Sigs instead. {{.Type}}FuncSigs maps the 4-byte function signature to its string representation.
		// 已弃用：使用 {{.Type}}MetaData.Sigs 代替。 {{.Type}}FuncSigs 将 4 字节函数签名映射到其字符串表示形式。
		var {{.Type}}FuncSigs = {{.Type}}MetaData.Sigs
	{{end}}

	{{if .InputBin}}
		// {{.Type}}Bin is the compiled bytecode used for deploying new contracts. Deprecated: Use {{.Type}}MetaData.Bin instead.
		// {{.Type}}Bin 是用于部署新合约的已编译字节码。已弃用：使用 {{.Type}}MetaData.Bin 代替。
		var {{.Type}}Bin = {{.Type}}MetaData.Bin

		// Deploy{{.Type}} deploys a new Ethereum contract, binding an instance of {{.Type}} to it.
		// Deploy{{.Type}} 部署一个新的以太坊合约，并将 {{.Type}} 的实例绑定到它。
		func Deploy{{.Type}}(auth *bind.TransactOpts, backend bind.ContractBackend {{range .Constructor.Inputs}}, {{.Name}} {{bindtype .Type $structs}}{{end}}) (common.Address, *types.Transaction, *{{.Type}}, error) {
		  parsed, err := {{.Type}}MetaData.GetAbi()
		  if err != nil {
		    return common.Address{}, nil, nil, err
		  }
		  if parsed == nil {
			return common.Address{}, nil, nil, errors.New("GetABI returned nil")
		  }
		  {{range $pattern, $name := .Libraries}}
			{{decapitalise $name}}Addr, _, _, _ := Deploy{{capitalise $name}}(auth, backend)
			{{$contract.Type}}Bin = strings.ReplaceAll({{$contract.Type}}Bin, "__${{$pattern}}$__", {{decapitalise $name}}Addr.String()[2:])
		  {{end}}
		  address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex({{.Type}}Bin), backend {{range .Constructor.Inputs}}, {{.Name}}{{end}})
		  if err != nil {
		    return common.Address{}, nil, nil, err
		  }
		  return address, tx, &{{.Type}}{ {{.Type}}Caller: {{.Type}}Caller{contract: contract}, {{.Type}}Transactor: {{.Type}}Transactor{contract: contract}, {{.Type}}Filterer: {{.Type}}Filterer{contract: contract} }, nil
		}
	{{end}}

	// {{.Type}} is an auto generated Go binding around an Ethereum contract.
	// {{.Type}} 是围绕以太坊合约自动生成的 Go 绑定。
	type {{.Type}} struct {
	  {{.Type}}Caller     // Read-only binding to the contract // 只读绑定合约
	  {{.Type}}Transactor // Write-only binding to the contract // 只写绑定到合约
	  {{.Type}}Filterer   // Log filterer for contract events // 合约事件的日志过滤器
	}

	// {{.Type}}Caller is an auto generated read-only Go binding around an Ethereum contract.
	// {{.Type}}Caller 是围绕以太坊合约自动生成的只读 Go 绑定。
	type {{.Type}}Caller struct {
	  contract *bind.BoundContract // Generic contract wrapper for the low level calls // 用于低级调用的通用合约包装器
	}

	// {{.Type}}Transactor is an auto generated write-only Go binding around an Ethereum contract.
	// {{.Type}}Transactor 是围绕以太坊合约自动生成的只写 Go 绑定。
	type {{.Type}}Transactor struct {
	  contract *bind.BoundContract // Generic contract wrapper for the low level calls // 用于低级调用的通用合约包装器
	}

	// {{.Type}}Filterer is an auto generated log filtering Go binding around an Ethereum contract events.
	// {{.Type}}Filterer 是一个自动生成的日志过滤 Go 绑定，围绕以太坊合约事件。
	type {{.Type}}Filterer struct {
	  contract *bind.BoundContract // Generic contract wrapper for the low level calls // 用于低级调用的通用合约包装器
	}

	// {{.Type}}Session is an auto generated Go binding around an Ethereum contract, with pre-set call and transact options.
	// {{.Type}}Session 是围绕以太坊合约自动生成的 Go 绑定，具有预设的调用和交易选项。
	type {{.Type}}Session struct {
	  Contract     *{{.Type}}        // Generic contract binding to set the session for // 用于设置会话的通用合约绑定
	  CallOpts     bind.CallOpts     // Call options to use throughout this session // 在整个会话中使用的调用选项
	  TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session // 在整个会话中使用的交易验证选项
	}

	// {{.Type}}CallerSession is an auto generated read-only Go binding around an Ethereum contract, with pre-set call options.
	// {{.Type}}CallerSession 是围绕以太坊合约自动生成的只读 Go 绑定，具有预设的调用选项。
	type {{.Type}}CallerSession struct {
	  Contract *{{.Type}}Caller // Generic contract caller binding to set the session for // 用于设置会话的通用合约调用者绑定
	  CallOpts bind.CallOpts    // Call options to use throughout this session // 在整个会话中使用的调用选项
	}

	// {{.Type}}TransactorSession is an auto generated write-only Go binding around an Ethereum contract, with pre-set transact options.
	// {{.Type}}TransactorSession 是围绕以太坊合约自动生成的只写 Go 绑定，具有预设的交易选项。
	type {{.Type}}TransactorSession struct {
	  Contract     *{{.Type}}Transactor // Generic contract transactor binding to set the session for // 用于设置会话的通用合约交易者绑定
	  TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session // 在整个会话中使用的交易验证选项
	}

	// {{.Type}}Raw is an auto generated low-level Go binding around an Ethereum contract.
	// {{.Type}}Raw 是围绕以太坊合约自动生成的低级 Go 绑定。
	type {{.Type}}Raw struct {
	  Contract *{{.Type}} // Generic contract binding to access the raw methods on // 用于访问原始方法的通用合约绑定
	}

	// {{.Type}}CallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
	// {{.Type}}CallerRaw 是围绕以太坊合约自动生成的低级只读 Go 绑定。
	type {{.Type}}CallerRaw struct {
		Contract *{{.Type}}Caller // Generic read-only contract binding to access the raw methods on // 用于访问原始方法的通用只读合约绑定
	}

	// {{.Type}}TransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
	// {{.Type}}TransactorRaw 是围绕以太坊合约自动生成的低级只写 Go 绑定。
	type {{.Type}}TransactorRaw struct {
		Contract *{{.Type}}Transactor // Generic write-only contract binding to access the raw methods on // 用于访问原始方法的通用只写合约绑定
	}

	// New{{.Type}} creates a new instance of {{.Type}}, bound to a specific deployed contract.
	// New{{.Type}} 创建一个新的 {{.Type}} 实例，绑定到特定的已部署合约。
	func New{{.Type}}(address common.Address, backend bind.ContractBackend) (*{{.Type}}, error) {
	  contract, err := bind{{.Type}}(address, backend, backend, backend)
	  if err != nil {
	    return nil, err
	  }
	  return &{{.Type}}{ {{.Type}}Caller: {{.Type}}Caller{contract: contract}, {{.Type}}Transactor: {{.Type}}Transactor{contract: contract}, {{.Type}}Filterer: {{.Type}}Filterer{contract: contract} }, nil
	}

	// New{{.Type}}Caller creates a new read-only instance of {{.Type}}, bound to a specific deployed contract.
	// New{{.Type}}调用者创建一个新的 {{.Type}} 只读实例，绑定到特定的已部署合约。
	func New{{.Type}}Caller(address common.Address, caller bind.ContractCaller) (*{{.Type}}Caller, error) {
	  contract, err := bind{{.Type}}(address, caller, nil, nil)
	  if err != nil {
	    return nil, err
	  }
	  return &{{.Type}}Caller{contract: contract}, nil
	}

	// New{{.Type}}Transactor creates a new write-only instance of {{.Type}}, bound to a specific deployed contract.
	// New{{.Type}}Transactor 创建一个新的 {{.Type}} 只写实例，绑定到特定的已部署合约。
	func New{{.Type}}Transactor(address common.Address, transactor bind.ContractTransactor) (*{{.Type}}Transactor, error) {
	  contract, err := bind{{.Type}}(address, nil, transactor, nil)
	  if err != nil {
	    return nil, err
	  }
	  return &{{.Type}}Transactor{contract: contract}, nil
	}

	// New{{.Type}}Filterer creates a new log filterer instance of {{.Type}}, bound to a specific deployed contract.
	// New{{.Type}}Filterer 创建一个新的 {{.Type}} 日志过滤器实例，绑定到特定的已部署合约。
 	func New{{.Type}}Filterer(address common.Address, filterer bind.ContractFilterer) (*{{.Type}}Filterer, error) {
 	  contract, err := bind{{.Type}}(address, nil, nil, filterer)
 	  if err != nil {
 	    return nil, err
 	  }
 	  return &{{.Type}}Filterer{contract: contract}, nil
 	}

	// bind{{.Type}} binds a generic wrapper to an already deployed contract.
	// bind{{.Type}} 将通用包装器绑定到已部署的合约。
	func bind{{.Type}}(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	  parsed, err := {{.Type}}MetaData.GetAbi()
	  if err != nil {
	    return nil, err
	  }
	  return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
	}

	// Call invokes the (constant) contract method with params as input values and sets the output to result. The result type might be a single field for simple returns, a slice of interfaces for anonymous returns and a struct for named returns.
	// Call 使用 params 作为输入值调用（常量）合约方法，并将输出设置为 result。结果类型可能是用于简单返回的单个字段、用于匿名返回的接口切片以及用于命名返回的结构。
	func (_{{$contract.Type}} *{{$contract.Type}}Raw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
		return _{{$contract.Type}}.Contract.{{$contract.Type}}Caller.contract.Call(opts, result, method, params...)
	}

	// Transfer initiates a plain transaction to move funds to the contract, calling its default method if one is available.
	// Transfer 启动一项普通交易，将资金转移到合约中，并调用其默认方法（如果可用）。
	func (_{{$contract.Type}} *{{$contract.Type}}Raw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
		return _{{$contract.Type}}.Contract.{{$contract.Type}}Transactor.contract.Transfer(opts)
	}

	// Transact invokes the (paid) contract method with params as input values.
	// Transact 使用 params 作为输入值调用（付费）合约方法。
	func (_{{$contract.Type}} *{{$contract.Type}}Raw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
		return _{{$contract.Type}}.Contract.{{$contract.Type}}Transactor.contract.Transact(opts, method, params...)
	}

	// Call invokes the (constant) contract method with params as input values and sets the output to result. The result type might be a single field for simple returns, a slice of interfaces for anonymous returns and a struct for named returns.
	// Call 使用 params 作为输入值调用（常量）合约方法，并将输出设置为 result。结果类型可能是用于简单返回的单个字段、用于匿名返回的接口切片以及用于命名返回的结构。
	func (_{{$contract.Type}} *{{$contract.Type}}CallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
		return _{{$contract.Type}}.Contract.contract.Call(opts, result, method, params...)
	}

	// Transfer initiates a plain transaction to move funds to the contract, calling its default method if one is available.
	// Transfer 启动一项普通交易，将资金转移到合约中，并调用其默认方法（如果可用）。
	func (_{{$contract.Type}} *{{$contract.Type}}TransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
		return _{{$contract.Type}}.Contract.contract.Transfer(opts)
	}

	// Transact invokes the (paid) contract method with params as input values.
	// Transact 使用 params 作为输入值调用（付费）合约方法。
	func (_{{$contract.Type}} *{{$contract.Type}}TransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
		return _{{$contract.Type}}.Contract.contract.Transact(opts, method, params...)
	}

	{{range .Calls}}
		// {{.Normalized.Name}} is a free data retrieval call binding the contract method 0x{{printf "%x" .Original.ID}}.
		// {{.Normalized.Name}} 是绑定合约方法 0x{{printf "%x" .Original.ID}} 的免费数据检索调用。
		// Solidity: {{.Original.String}}
		// 坚固性：{{.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}Caller) {{.Normalized.Name}}(opts *bind.CallOpts {{range .Normalized.Inputs}}, {{.Name}} {{bindtype .Type $structs}} {{end}}) ({{if .Structured}}struct{ {{range .Normalized.Outputs}}{{.Name}} {{bindtype .Type $structs}};{{end}} },{{else}}{{range .Normalized.Outputs}}{{bindtype .Type $structs}},{{end}}{{end}} error) {
			var out []interface{}
			err := _{{$contract.Type}}.contract.Call(opts, &out, "{{.Original.Name}}" {{range .Normalized.Inputs}}, {{.Name}}{{end}})
			{{if .Structured}}
			outstruct := new(struct{ {{range .Normalized.Outputs}} {{.Name}} {{bindtype .Type $structs}}; {{end}} })
			if err != nil {
				return *outstruct, err
			}
			{{range $i, $t := .Normalized.Outputs}}
			outstruct.{{.Name}} = *abi.ConvertType(out[{{$i}}], new({{bindtype .Type $structs}})).(*{{bindtype .Type $structs}}){{end}}

			return *outstruct, err
			{{else}}
			if err != nil {
				return {{range $i, $_ := .Normalized.Outputs}}*new({{bindtype .Type $structs}}), {{end}} err
			}
			{{range $i, $t := .Normalized.Outputs}}
			out{{$i}} := *abi.ConvertType(out[{{$i}}], new({{bindtype .Type $structs}})).(*{{bindtype .Type $structs}}){{end}}

			return {{range $i, $t := .Normalized.Outputs}}out{{$i}}, {{end}} err
			{{end}}
		}

		// {{.Normalized.Name}} is a free data retrieval call binding the contract method 0x{{printf "%x" .Original.ID}}.
		// {{.Normalized.Name}} 是绑定合约方法 0x{{printf "%x" .Original.ID}} 的免费数据检索调用。
		// Solidity: {{.Original.String}}
		// 坚固性：{{.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}Session) {{.Normalized.Name}}({{range $i, $_ := .Normalized.Inputs}}{{if ne $i 0}},{{end}} {{.Name}} {{bindtype .Type $structs}} {{end}}) ({{if .Structured}}struct{ {{range .Normalized.Outputs}}{{.Name}} {{bindtype .Type $structs}};{{end}} }, {{else}} {{range .Normalized.Outputs}}{{bindtype .Type $structs}},{{end}} {{end}} error) {
		  return _{{$contract.Type}}.Contract.{{.Normalized.Name}}(&_{{$contract.Type}}.CallOpts {{range .Normalized.Inputs}}, {{.Name}}{{end}})
		}

		// {{.Normalized.Name}} is a free data retrieval call binding the contract method 0x{{printf "%x" .Original.ID}}.
		// {{.Normalized.Name}} 是绑定合约方法 0x{{printf "%x" .Original.ID}} 的免费数据检索调用。
		// Solidity: {{.Original.String}}
		// 坚固性：{{.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}CallerSession) {{.Normalized.Name}}({{range $i, $_ := .Normalized.Inputs}}{{if ne $i 0}},{{end}} {{.Name}} {{bindtype .Type $structs}} {{end}}) ({{if .Structured}}struct{ {{range .Normalized.Outputs}}{{.Name}} {{bindtype .Type $structs}};{{end}} }, {{else}} {{range .Normalized.Outputs}}{{bindtype .Type $structs}},{{end}} {{end}} error) {
		  return _{{$contract.Type}}.Contract.{{.Normalized.Name}}(&_{{$contract.Type}}.CallOpts {{range .Normalized.Inputs}}, {{.Name}}{{end}})
		}
	{{end}}

	{{range .Transacts}}
		// {{.Normalized.Name}} is a paid mutator transaction binding the contract method 0x{{printf "%x" .Original.ID}}.
		// {{.Normalized.Name}} 是绑定合约方法 0x{{printf "%x" .Original.ID}} 的付费变异器交易。
		// Solidity: {{.Original.String}}
		// 坚固性：{{.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}Transactor) {{.Normalized.Name}}(opts *bind.TransactOpts {{range .Normalized.Inputs}}, {{.Name}} {{bindtype .Type $structs}} {{end}}) (*types.Transaction, error) {
			return _{{$contract.Type}}.contract.Transact(opts, "{{.Original.Name}}" {{range .Normalized.Inputs}}, {{.Name}}{{end}})
		}

		// {{.Normalized.Name}} is a paid mutator transaction binding the contract method 0x{{printf "%x" .Original.ID}}.
		// {{.Normalized.Name}} 是绑定合约方法 0x{{printf "%x" .Original.ID}} 的付费变异器交易。
		// Solidity: {{.Original.String}}
		// 坚固性：{{.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}Session) {{.Normalized.Name}}({{range $i, $_ := .Normalized.Inputs}}{{if ne $i 0}},{{end}} {{.Name}} {{bindtype .Type $structs}} {{end}}) (*types.Transaction, error) {
		  return _{{$contract.Type}}.Contract.{{.Normalized.Name}}(&_{{$contract.Type}}.TransactOpts {{range $i, $_ := .Normalized.Inputs}}, {{.Name}}{{end}})
		}

		// {{.Normalized.Name}} is a paid mutator transaction binding the contract method 0x{{printf "%x" .Original.ID}}.
		// {{.Normalized.Name}} 是绑定合约方法 0x{{printf "%x" .Original.ID}} 的付费变异器交易。
		// Solidity: {{.Original.String}}
		// 坚固性：{{.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}TransactorSession) {{.Normalized.Name}}({{range $i, $_ := .Normalized.Inputs}}{{if ne $i 0}},{{end}} {{.Name}} {{bindtype .Type $structs}} {{end}}) (*types.Transaction, error) {
		  return _{{$contract.Type}}.Contract.{{.Normalized.Name}}(&_{{$contract.Type}}.TransactOpts {{range $i, $_ := .Normalized.Inputs}}, {{.Name}}{{end}})
		}
	{{end}}

	{{if .Fallback}}
		// Fallback is a paid mutator transaction binding the contract fallback function.
		// Fallback 是绑定合约 Fallback 功能的付费变元交易。
		// Solidity: {{.Fallback.Original.String}}
		// 坚固性：{{.Fallback.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}Transactor) Fallback(opts *bind.TransactOpts, calldata []byte) (*types.Transaction, error) {
			return _{{$contract.Type}}.contract.RawTransact(opts, calldata)
		}

		// Fallback is a paid mutator transaction binding the contract fallback function.
		// Fallback 是绑定合约 Fallback 功能的付费变元交易。
		// Solidity: {{.Fallback.Original.String}}
		// 坚固性：{{.Fallback.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}Session) Fallback(calldata []byte) (*types.Transaction, error) {
		  return _{{$contract.Type}}.Contract.Fallback(&_{{$contract.Type}}.TransactOpts, calldata)
		}

		// Fallback is a paid mutator transaction binding the contract fallback function.
		// Fallback 是绑定合约 Fallback 功能的付费变元交易。
		// Solidity: {{.Fallback.Original.String}}
		// 坚固性：{{.Fallback.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}TransactorSession) Fallback(calldata []byte) (*types.Transaction, error) {
		  return _{{$contract.Type}}.Contract.Fallback(&_{{$contract.Type}}.TransactOpts, calldata)
		}
	{{end}}

	{{if .Receive}}
		// Receive is a paid mutator transaction binding the contract receive function.
		// 接收是绑定合约接收函数的付费变异器交易。
		// Solidity: {{.Receive.Original.String}}
		// 坚固性：{{.Receive.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}Transactor) Receive(opts *bind.TransactOpts) (*types.Transaction, error) {
			return _{{$contract.Type}}.contract.RawTransact(opts, nil) // calldata is disallowed for receive function // 接收功能不允许使用 calldata
		}

		// Receive is a paid mutator transaction binding the contract receive function.
		// 接收是绑定合约接收函数的付费变异器交易。
		// Solidity: {{.Receive.Original.String}}
		// 坚固性：{{.Receive.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}Session) Receive() (*types.Transaction, error) {
		  return _{{$contract.Type}}.Contract.Receive(&_{{$contract.Type}}.TransactOpts)
		}

		// Receive is a paid mutator transaction binding the contract receive function.
		// 接收是绑定合约接收函数的付费变异器交易。
		// Solidity: {{.Receive.Original.String}}
		// 坚固性：{{.Receive.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}TransactorSession) Receive() (*types.Transaction, error) {
		  return _{{$contract.Type}}.Contract.Receive(&_{{$contract.Type}}.TransactOpts)
		}
	{{end}}

	{{range .Events}}
		// {{$contract.Type}}{{.Normalized.Name}}Iterator is returned from Filter{{.Normalized.Name}} and is used to iterate over the raw logs and unpacked data for {{.Normalized.Name}} events raised by the {{$contract.Type}} contract.
		// {{$contract.Type}}{{.Normalized.Name}}迭代器从 Filter{{.Normalized.Name}} 返回，用于迭代 {{.Normalized.Name}} 的原始日志和解压数据由 {{$contract.Type}} 合约引发的事件。
		type {{$contract.Type}}{{.Normalized.Name}}Iterator struct {
			Event *{{$contract.Type}}{{.Normalized.Name}} // Event containing the contract specifics and raw log // 包含合同细节和原始日志的事件

			contract *bind.BoundContract // Generic contract to use for unpacking event data // 用于解包事件数据的通用合约
			event    string              // Event name to use for unpacking event data // 用于解包事件数据的事件名称

			logs chan types.Log        // Log channel receiving the found contract events // 接收发现的合约事件的日志通道
			sub  ethereum.Subscription // Subscription for errors, completion and termination // 订阅错误、完成和终止
			done bool                  // Whether the subscription completed delivering logs // 订阅是否完成日志下发
			fail error                 // Occurred error to stop iteration // 发生错误停止迭代
		}
		// Next advances the iterator to the subsequent event, returning whether there are any more events found. In case of a retrieval or parsing error, false is returned and Error() can be queried for the exact failure.
		// Next 将迭代器前进到后续事件，返回是否找到更多事件。如果出现检索或解析错误，则返回 false，并且可以查询 Error() 以获取确切的失败信息。
		func (it *{{$contract.Type}}{{.Normalized.Name}}Iterator) Next() bool {
			// If the iterator failed, stop iterating
			// 如果迭代器失败，则停止迭代
			if (it.fail != nil) {
				return false
			}
			// If the iterator completed, deliver directly whatever's available
			// 如果迭代器完成，则直接交付可用的内容
			if (it.done) {
				select {
				case log := <-it.logs:
					it.Event = new({{$contract.Type}}{{.Normalized.Name}})
					if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
						it.fail = err
						return false
					}
					it.Event.Raw = log
					return true

				default:
					return false
				}
			}
			// Iterator still in progress, wait for either a data or an error event
			// 迭代器仍在进行中，等待数据或错误事件
			select {
			case log := <-it.logs:
				it.Event = new({{$contract.Type}}{{.Normalized.Name}})
				if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
					it.fail = err
					return false
				}
				it.Event.Raw = log
				return true

			case err := <-it.sub.Err():
				it.done = true
				it.fail = err
				return it.Next()
			}
		}
		// Error returns any retrieval or parsing error occurred during filtering.
		// 错误返回过滤期间发生的任何检索或解析错误。
		func (it *{{$contract.Type}}{{.Normalized.Name}}Iterator) Error() error {
			return it.fail
		}
		// Close terminates the iteration process, releasing any pending underlying resources.
		// Close 终止迭代过程，释放任何挂起的底层资源。
		func (it *{{$contract.Type}}{{.Normalized.Name}}Iterator) Close() error {
			it.sub.Unsubscribe()
			return nil
		}

		// {{$contract.Type}}{{.Normalized.Name}} represents a {{.Normalized.Name}} event raised by the {{$contract.Type}} contract.
		// {{$contract.Type}}{{.Normalized.Name}} 表示由 {{$contract.Type}} 合约引发的 {{.Normalized.Name}} 事件。
		type {{$contract.Type}}{{.Normalized.Name}} struct { {{range .Normalized.Inputs}}
			{{capitalise .Name}} {{if .Indexed}}{{bindtopictype .Type $structs}}{{else}}{{bindtype .Type $structs}}{{end}}; {{end}}
			Raw types.Log // Blockchain specific contextual infos // 区块链特定上下文信息
		}

		// Filter{{.Normalized.Name}} is a free log retrieval operation binding the contract event 0x{{printf "%x" .Original.ID}}.
		// Filter{{.Normalized.Name}} 是绑定合约事件 0x{{printf "%x" .Original.ID}} 的免费日志检索操作。
		// Solidity: {{.Original.String}}
		// 坚固性：{{.Original.String}}
 		func (_{{$contract.Type}} *{{$contract.Type}}Filterer) Filter{{.Normalized.Name}}(opts *bind.FilterOpts{{range .Normalized.Inputs}}{{if .Indexed}}, {{.Name}} []{{bindtype .Type $structs}}{{end}}{{end}}) (*{{$contract.Type}}{{.Normalized.Name}}Iterator, error) {
			{{range .Normalized.Inputs}}
			{{if .Indexed}}var {{.Name}}Rule []interface{}
			for _, {{.Name}}Item := range {{.Name}} {
				{{.Name}}Rule = append({{.Name}}Rule, {{.Name}}Item)
			}{{end}}{{end}}

			logs, sub, err := _{{$contract.Type}}.contract.FilterLogs(opts, "{{.Original.Name}}"{{range .Normalized.Inputs}}{{if .Indexed}}, {{.Name}}Rule{{end}}{{end}})
			if err != nil {
				return nil, err
			}
			return &{{$contract.Type}}{{.Normalized.Name}}Iterator{contract: _{{$contract.Type}}.contract, event: "{{.Original.Name}}", logs: logs, sub: sub}, nil
 		}

		// Watch{{.Normalized.Name}} is a free log subscription operation binding the contract event 0x{{printf "%x" .Original.ID}}.
		// Watch{{.Normalized.Name}} 是绑定合约事件 0x{{printf "%x" .Original.ID}} 的免费日志订阅操作。
		// Solidity: {{.Original.String}}
		// 坚固性：{{.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}Filterer) Watch{{.Normalized.Name}}(opts *bind.WatchOpts, sink chan<- *{{$contract.Type}}{{.Normalized.Name}}{{range .Normalized.Inputs}}{{if .Indexed}}, {{.Name}} []{{bindtype .Type $structs}}{{end}}{{end}}) (event.Subscription, error) {
			{{range .Normalized.Inputs}}
			{{if .Indexed}}var {{.Name}}Rule []interface{}
			for _, {{.Name}}Item := range {{.Name}} {
				{{.Name}}Rule = append({{.Name}}Rule, {{.Name}}Item)
			}{{end}}{{end}}

			logs, sub, err := _{{$contract.Type}}.contract.WatchLogs(opts, "{{.Original.Name}}"{{range .Normalized.Inputs}}{{if .Indexed}}, {{.Name}}Rule{{end}}{{end}})
			if err != nil {
				return nil, err
			}
			return event.NewSubscription(func(quit <-chan struct{}) error {
				defer sub.Unsubscribe()
				for {
					select {
					case log := <-logs:
						// New log arrived, parse the event and forward to the user
						// 新日志到达，解析事件并转发给用户
						event := new({{$contract.Type}}{{.Normalized.Name}})
						if err := _{{$contract.Type}}.contract.UnpackLog(event, "{{.Original.Name}}", log); err != nil {
							return err
						}
						event.Raw = log

						select {
						case sink <- event:
						case err := <-sub.Err():
							return err
						case <-quit:
							return nil
						}
					case err := <-sub.Err():
						return err
					case <-quit:
						return nil
					}
				}
			}), nil
		}

		// Parse{{.Normalized.Name}} is a log parse operation binding the contract event 0x{{printf "%x" .Original.ID}}.
		// Parse{{.Normalized.Name}} 是绑定合约事件 0x{{printf "%x" .Original.ID}} 的日志解析操作。
		// Solidity: {{.Original.String}}
		// 坚固性：{{.Original.String}}
		func (_{{$contract.Type}} *{{$contract.Type}}Filterer) Parse{{.Normalized.Name}}(log types.Log) (*{{$contract.Type}}{{.Normalized.Name}}, error) {
			event := new({{$contract.Type}}{{.Normalized.Name}})
			if err := _{{$contract.Type}}.contract.UnpackLog(event, "{{.Original.Name}}", log); err != nil {
				return nil, err
			}
			event.Raw = log
			return event, nil
		}

 	{{end}}
{{end}}
`


