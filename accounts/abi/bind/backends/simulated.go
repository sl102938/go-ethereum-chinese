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

package backends

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
)

// SimulatedBackend is a simulated blockchain. Deprecated: use package github.com/ethereum/go-ethereum/ethclient/simulated instead.
// SimulatedBackend 是一个模拟区块链。已弃用：使用包 github.com/ethereum/go-ethereum/ethclient/simulated 代替。
type SimulatedBackend struct {
	*simulated.Backend
	simulated.Client
}

// Fork sets the head to a new block, which is based on the provided parentHash.
// Fork 将头设置为新块，该新块基于提供的parentHash。
func (b *SimulatedBackend) Fork(ctx context.Context, parentHash common.Hash) error {
	return b.Backend.Fork(parentHash)
}

// NewSimulatedBackend creates a new binding backend using a simulated blockchain for testing purposes.
// NewSimulatedBackend 使用模拟区块链创建一个新的绑定后端以进行测试。
// A simulated backend always uses chainID 1337.
// 模拟后端始终使用 chainID 1337。
// Deprecated: please use simulated.Backend from package github.com/ethereum/go-ethereum/ethclient/simulated instead.
// 已弃用：请使用 github.com/ethereum/go-ethereum/ethclient/simulated 包中的simulated.Backend 代替。
func NewSimulatedBackend(alloc types.GenesisAlloc, gasLimit uint64) *SimulatedBackend {
	b := simulated.NewBackend(alloc, simulated.WithBlockGasLimit(gasLimit))
	return &SimulatedBackend{
		Backend: b,
		Client:  b.Client(),
	}
}


