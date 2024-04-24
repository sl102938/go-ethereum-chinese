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
	"reflect"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/event"
)

// managerSubBufferSize determines how many incoming wallet events the manager will buffer in its channel.
// managerSubBufferSize 确定管理器将在其通道中缓冲多少传入钱包事件。
const managerSubBufferSize = 50

// Config contains the settings of the global account manager.
// 配置包含全局账户管理器的设置。
// TODO(rjl493456442, karalabe, holiman): Get rid of this when account management is removed in favor of Clef.
// TODO（rjl493456442，karalabe，holiman）：当帐户管理被删除以支持 Clef 时，请摆脱此问题。
type Config struct {
	InsecureUnlockAllowed bool // Whether account unlocking in insecure environment is allowed // 是否允许在不安全环境下解锁账户
}

// newBackendEvent lets the manager know it should track the given backend for wallet updates.
// newBackendEvent 让管理器知道它应该跟踪给定的后端以获取钱包更新。
type newBackendEvent struct {
	backend   Backend
	processed chan struct{} // Informs event emitter that backend has been integrated // 通知事件发射器后端已集成
}

// Manager is an overarching account manager that can communicate with various backends for signing transactions.
// Manager 是一个总体客户经理，可以与各种后端通信以签署交易。
type Manager struct {
	config      *Config                    // Global account manager configurations // 全球客户经理配置
	backends    map[reflect.Type][]Backend // Index of backends currently registered // 当前注册的后端索引
	updaters    []event.Subscription       // Wallet update subscriptions for all backends // 所有后端的钱包更新订阅
	updates     chan WalletEvent           // Subscription sink for backend wallet changes // 后端钱包变更的订阅接收器
	newBackends chan newBackendEvent       // Incoming backends to be tracked by the manager // 由经理跟踪传入后端
	wallets     []Wallet                   // Cache of all wallets from all registered backends // 缓存所有已注册后端的所有钱包

	feed event.Feed // Wallet feed notifying of arrivals/departures // 通知到达/出发的钱包信息

	quit chan chan error
	term chan struct{} // Channel is closed upon termination of the update loop // 更新循环终止时通道关闭
	lock sync.RWMutex
}

// NewManager creates a generic account manager to sign transaction via various supported backends.
// NewManager 创建一个通用帐户经理来通过各种支持的后端签署交易。
func NewManager(config *Config, backends ...Backend) *Manager {
	// Retrieve the initial list of wallets from the backends and sort by URL
	// 从后端检索初始钱包列表并按 URL 排序
	var wallets []Wallet
	for _, backend := range backends {
		wallets = merge(wallets, backend.Wallets()...)
	}
	// Subscribe to wallet notifications from all backends
	// 订阅所有后端的钱包通知
	updates := make(chan WalletEvent, managerSubBufferSize)

	subs := make([]event.Subscription, len(backends))
	for i, backend := range backends {
		subs[i] = backend.Subscribe(updates)
	}
	// Assemble the account manager and return
	// 集合客户经理并返回
	am := &Manager{
		config:      config,
		backends:    make(map[reflect.Type][]Backend),
		updaters:    subs,
		updates:     updates,
		newBackends: make(chan newBackendEvent),
		wallets:     wallets,
		quit:        make(chan chan error),
		term:        make(chan struct{}),
	}
	for _, backend := range backends {
		kind := reflect.TypeOf(backend)
		am.backends[kind] = append(am.backends[kind], backend)
	}
	go am.update()

	return am
}

// Close terminates the account manager's internal notification processes.
// 关闭会终止客户经理的内部通知流程。
func (am *Manager) Close() error {
	for _, w := range am.wallets {
		w.Close()
	}
	errc := make(chan error)
	am.quit <- errc
	return <-errc
}

// Config returns the configuration of account manager.
// Config 返回账户管理器的配置。
func (am *Manager) Config() *Config {
	return am.config
}

// AddBackend starts the tracking of an additional backend for wallet updates. cmd/geth assumes once this func returns the backends have been already integrated.
// AddBackend 开始跟踪钱包更新的附加后端。 cmd/geth 假设一旦该函数返回，后端就已经集成。
func (am *Manager) AddBackend(backend Backend) {
	done := make(chan struct{})
	am.newBackends <- newBackendEvent{backend, done}
	<-done
}

// update is the wallet event loop listening for notifications from the backends and updating the cache of wallets.
// update 是钱包事件循环，监听来自后端的通知并更新钱包的缓存。
func (am *Manager) update() {
	// Close all subscriptions when the manager terminates
	// 当管理器终止时关闭所有订阅
	defer func() {
		am.lock.Lock()
		for _, sub := range am.updaters {
			sub.Unsubscribe()
		}
		am.updaters = nil
		am.lock.Unlock()
	}()

	// Loop until termination
	// 循环直到终止
	for {
		select {
		case event := <-am.updates:
			// Wallet event arrived, update local cache
			// 钱包事件到达，更新本地缓存
			am.lock.Lock()
			switch event.Kind {
			case WalletArrived:
				am.wallets = merge(am.wallets, event.Wallet)
			case WalletDropped:
				am.wallets = drop(am.wallets, event.Wallet)
			}
			am.lock.Unlock()

			// Notify any listeners of the event
			// 通知所有监听者该事件
			am.feed.Send(event)
		case event := <-am.newBackends:
			am.lock.Lock()
			// Update caches
			// 更新缓存
			backend := event.backend
			am.wallets = merge(am.wallets, backend.Wallets()...)
			am.updaters = append(am.updaters, backend.Subscribe(am.updates))
			kind := reflect.TypeOf(backend)
			am.backends[kind] = append(am.backends[kind], backend)
			am.lock.Unlock()
			close(event.processed)
		case errc := <-am.quit:
			// Manager terminating, return
			// 经理终止，返回
			errc <- nil
			// Signals event emitters the loop is not receiving values to prevent them from getting stuck.
			// 向事件发射器发出循环未接收值的信号，以防止它们陷入困境。
			close(am.term)
			return
		}
	}
}

// Backends retrieves the backend(s) with the given type from the account manager.
// 后端从客户经理处检索具有给定类型的后端。
func (am *Manager) Backends(kind reflect.Type) []Backend {
	am.lock.RLock()
	defer am.lock.RUnlock()

	return am.backends[kind]
}

// Wallets returns all signer accounts registered under this account manager.
// 钱包返回在该客户经理下注册的所有签名者帐户。
func (am *Manager) Wallets() []Wallet {
	am.lock.RLock()
	defer am.lock.RUnlock()

	return am.walletsNoLock()
}

// walletsNoLock returns all registered wallets. Callers must hold am.lock.
// walletsNoLock 返回所有已注册的钱包。调用者必须持有 am.lock。
func (am *Manager) walletsNoLock() []Wallet {
	cpy := make([]Wallet, len(am.wallets))
	copy(cpy, am.wallets)
	return cpy
}

// Wallet retrieves the wallet associated with a particular URL.
// 钱包检索与特定 URL 关联的钱包。
func (am *Manager) Wallet(url string) (Wallet, error) {
	am.lock.RLock()
	defer am.lock.RUnlock()

	parsed, err := parseURL(url)
	if err != nil {
		return nil, err
	}
	for _, wallet := range am.walletsNoLock() {
		if wallet.URL() == parsed {
			return wallet, nil
		}
	}
	return nil, ErrUnknownWallet
}

// Accounts returns all account addresses of all wallets within the account manager
// Accounts返回账户管理器内所有钱包的所有账户地址
func (am *Manager) Accounts() []common.Address {
	am.lock.RLock()
	defer am.lock.RUnlock()

	addresses := make([]common.Address, 0) // return [] instead of nil if empty // 如果为空则返回 [] 而不是 nil
	for _, wallet := range am.wallets {
		for _, account := range wallet.Accounts() {
			addresses = append(addresses, account.Address)
		}
	}
	return addresses
}

// Find attempts to locate the wallet corresponding to a specific account. Since accounts can be dynamically added to and removed from wallets, this method has a linear runtime in the number of wallets.
// 查找尝试查找与特定帐户对应的钱包。由于账户可以动态地添加到钱包和从钱包中删除，因此该方法在钱包数量上具有线性运行时间。
func (am *Manager) Find(account Account) (Wallet, error) {
	am.lock.RLock()
	defer am.lock.RUnlock()

	for _, wallet := range am.wallets {
		if wallet.Contains(account) {
			return wallet, nil
		}
	}
	return nil, ErrUnknownAccount
}

// Subscribe creates an async subscription to receive notifications when the manager detects the arrival or departure of a wallet from any of its backends.
// 订阅创建一个异步订阅，以便在管理器检测到钱包从其任何后端到达或离开时接收通知。
func (am *Manager) Subscribe(sink chan<- WalletEvent) event.Subscription {
	return am.feed.Subscribe(sink)
}

// merge is a sorted analogue of append for wallets, where the ordering of the origin list is preserved by inserting new wallets at the correct position.
// merge 是钱包追加的排序类似物，其中通过在正确位置插入新钱包来保留原始列表的顺序。
// The original slice is assumed to be already sorted by URL.
// 假定原始切片已按 URL 排序。
func merge(slice []Wallet, wallets ...Wallet) []Wallet {
	for _, wallet := range wallets {
		n := sort.Search(len(slice), func(i int) bool { return slice[i].URL().Cmp(wallet.URL()) >= 0 })
		if n == len(slice) {
			slice = append(slice, wallet)
			continue
		}
		slice = append(slice[:n], append([]Wallet{wallet}, slice[n:]...)...)
	}
	return slice
}

// drop is the counterpart of merge, which looks up wallets from within the sorted cache and removes the ones specified.
// drop 是 merge 的对应项，它从排序的缓存中查找钱包并删除指定的钱包。
func drop(slice []Wallet, wallets ...Wallet) []Wallet {
	for _, wallet := range wallets {
		n := sort.Search(len(slice), func(i int) bool { return slice[i].URL().Cmp(wallet.URL()) >= 0 })
		if n == len(slice) {
			// Wallet not found, may happen during startup
			// 未找到钱包，可能在启动期间发生
			continue
		}
		slice = append(slice[:n], slice[n+1:]...)
	}
	return slice
}


