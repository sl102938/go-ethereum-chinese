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

package keystore

import (
	"math/rand"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
)

var testSigData = make([]byte, 32)

func TestKeyStore(t *testing.T) {
	t.Parallel()
	dir, ks := tmpKeyStore(t)

	a, err := ks.NewAccount("foo")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a.URL.Path, dir) {
		t.Errorf("account file %s doesn't have dir prefix", a.URL)
	}
	stat, err := os.Stat(a.URL.Path)
	if err != nil {
		t.Fatalf("account file %s doesn't exist (%v)", a.URL, err)
	}
	if runtime.GOOS != "windows" && stat.Mode() != 0600 {
		t.Fatalf("account file has wrong mode: got %o, want %o", stat.Mode(), 0600)
	}
	if !ks.HasAddress(a.Address) {
		t.Errorf("HasAccount(%x) should've returned true", a.Address)
	}
	if err := ks.Update(a, "foo", "bar"); err != nil {
		t.Errorf("Update error: %v", err)
	}
	if err := ks.Delete(a, "bar"); err != nil {
		t.Errorf("Delete error: %v", err)
	}
	if common.FileExist(a.URL.Path) {
		t.Errorf("account file %s should be gone after Delete", a.URL)
	}
	if ks.HasAddress(a.Address) {
		t.Errorf("HasAccount(%x) should've returned true after Delete", a.Address)
	}
}

func TestSign(t *testing.T) {
	t.Parallel()
	_, ks := tmpKeyStore(t)

	pass := "" // not used but required by API // 未使用但 API 需要
	a1, err := ks.NewAccount(pass)
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Unlock(a1, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.SignHash(accounts.Account{Address: a1.Address}, testSigData); err != nil {
		t.Fatal(err)
	}
}

func TestSignWithPassphrase(t *testing.T) {
	t.Parallel()
	_, ks := tmpKeyStore(t)

	pass := "passwd"
	acc, err := ks.NewAccount(pass)
	if err != nil {
		t.Fatal(err)
	}

	if _, unlocked := ks.unlocked[acc.Address]; unlocked {
		t.Fatal("expected account to be locked")
	}

	_, err = ks.SignHashWithPassphrase(acc, pass, testSigData)
	if err != nil {
		t.Fatal(err)
	}

	if _, unlocked := ks.unlocked[acc.Address]; unlocked {
		t.Fatal("expected account to be locked")
	}

	if _, err = ks.SignHashWithPassphrase(acc, "invalid passwd", testSigData); err == nil {
		t.Fatal("expected SignHashWithPassphrase to fail with invalid password")
	}
}

func TestTimedUnlock(t *testing.T) {
	t.Parallel()
	_, ks := tmpKeyStore(t)

	pass := "foo"
	a1, err := ks.NewAccount(pass)
	if err != nil {
		t.Fatal(err)
	}

	// Signing without passphrase fails because account is locked
	// 由于帐户被锁定，没有密码的签名失败
	_, err = ks.SignHash(accounts.Account{Address: a1.Address}, testSigData)
	if err != ErrLocked {
		t.Fatal("Signing should've failed with ErrLocked before unlocking, got ", err)
	}

	// Signing with passphrase works
	// 使用密码签名有效
	if err = ks.TimedUnlock(a1, pass, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	// Signing without passphrase works because account is temp unlocked
	// 由于帐户已临时解锁，因此无需密码即可进行签名
	_, err = ks.SignHash(accounts.Account{Address: a1.Address}, testSigData)
	if err != nil {
		t.Fatal("Signing shouldn't return an error after unlocking, got ", err)
	}

	// Signing fails again after automatic locking
	// 自动锁定后再次签名失败
	time.Sleep(250 * time.Millisecond)
	_, err = ks.SignHash(accounts.Account{Address: a1.Address}, testSigData)
	if err != ErrLocked {
		t.Fatal("Signing should've failed with ErrLocked timeout expired, got ", err)
	}
}

func TestOverrideUnlock(t *testing.T) {
	t.Parallel()
	_, ks := tmpKeyStore(t)

	pass := "foo"
	a1, err := ks.NewAccount(pass)
	if err != nil {
		t.Fatal(err)
	}

	// Unlock indefinitely.
	// 无限期解锁。
	if err = ks.TimedUnlock(a1, pass, 5*time.Minute); err != nil {
		t.Fatal(err)
	}

	// Signing without passphrase works because account is temp unlocked
	// 由于帐户已临时解锁，因此无需密码即可进行签名
	_, err = ks.SignHash(accounts.Account{Address: a1.Address}, testSigData)
	if err != nil {
		t.Fatal("Signing shouldn't return an error after unlocking, got ", err)
	}

	// reset unlock to a shorter period, invalidates the previous unlock
	// 将解锁重置为更短的时间，使之前的解锁失效
	if err = ks.TimedUnlock(a1, pass, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	// Signing without passphrase still works because account is temp unlocked
	// 没有密码的签名仍然有效，因为帐户已临时解锁
	_, err = ks.SignHash(accounts.Account{Address: a1.Address}, testSigData)
	if err != nil {
		t.Fatal("Signing shouldn't return an error after unlocking, got ", err)
	}

	// Signing fails again after automatic locking
	// 自动锁定后再次签名失败
	time.Sleep(250 * time.Millisecond)
	_, err = ks.SignHash(accounts.Account{Address: a1.Address}, testSigData)
	if err != ErrLocked {
		t.Fatal("Signing should've failed with ErrLocked timeout expired, got ", err)
	}
}

// This test should fail under -race if signing races the expiration goroutine.
// 如果签名与到期 Goroutine 发生竞争，则此测试应该在 -race 下失败。
func TestSignRace(t *testing.T) {
	t.Parallel()
	_, ks := tmpKeyStore(t)

	// Create a test account.
	// 创建一个测试帐户。
	a1, err := ks.NewAccount("")
	if err != nil {
		t.Fatal("could not create the test account", err)
	}

	if err := ks.TimedUnlock(a1, "", 15*time.Millisecond); err != nil {
		t.Fatal("could not unlock the test account", err)
	}
	end := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(end) {
		if _, err := ks.SignHash(accounts.Account{Address: a1.Address}, testSigData); err == ErrLocked {
			return
		} else if err != nil {
			t.Errorf("Sign error: %v", err)
			return
		}
		time.Sleep(1 * time.Millisecond)
	}
	t.Errorf("Account did not lock within the timeout")
}

// waitForKsUpdating waits until the updating-status of the ks reaches the desired wantStatus. It waits for a maximum time of maxTime, and returns false if it does not finish in time
// waitForKsUpdating 等待，直到 ks 的更新状态达到所需的wantStatus。它等待的最长时间为 maxTime，如果没有及时完成则返回 false
func waitForKsUpdating(t *testing.T, ks *KeyStore, wantStatus bool, maxTime time.Duration) bool {
	t.Helper()
	// Wait max 250 ms, then return false
	// 最多等待 250 毫秒，然后返回 false
	for t0 := time.Now(); time.Since(t0) < maxTime; {
		if ks.isUpdating() == wantStatus {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

// Tests that the wallet notifier loop starts and stops correctly based on the addition and removal of wallet event subscriptions.
// 测试钱包通知程序循环是否根据钱包事件订阅的添加和删除正确启动和停止。
func TestWalletNotifierLifecycle(t *testing.T) {
	t.Parallel()
	// Create a temporary keystore to test with
	// 创建一个临时密钥库进行测试
	_, ks := tmpKeyStore(t)

	// Ensure that the notification updater is not running yet
	// 确保通知更新程序尚未运行
	time.Sleep(250 * time.Millisecond)

	if ks.isUpdating() {
		t.Errorf("wallet notifier running without subscribers")
	}
	// Subscribe to the wallet feed and ensure the updater boots up
	// 订阅钱包源并确保更新程序启动
	updates := make(chan accounts.WalletEvent)

	subs := make([]event.Subscription, 2)
	for i := 0; i < len(subs); i++ {
		// Create a new subscription
		// 创建新订阅
		subs[i] = ks.Subscribe(updates)
		if !waitForKsUpdating(t, ks, true, 250*time.Millisecond) {
			t.Errorf("sub %d: wallet notifier not running after subscription", i)
		}
	}
	// Close all but one sub
	// 关闭除一个子项之外的所有子项
	for i := 0; i < len(subs)-1; i++ {
		// Close an existing subscription
		// 关闭现有订阅
		subs[i].Unsubscribe()
	}
	// Check that it is still running
	// 检查它是否仍在运行
	time.Sleep(250 * time.Millisecond)

	if !ks.isUpdating() {
		t.Fatal("event notifier stopped prematurely")
	}
	// Unsubscribe the last one and ensure the updater terminates eventually.
	// 取消订阅最后一个并确保更新程序最终终止。
	subs[len(subs)-1].Unsubscribe()
	if !waitForKsUpdating(t, ks, false, 4*time.Second) {
		t.Errorf("wallet notifier didn't terminate after unsubscribe")
	}
}

type walletEvent struct {
	accounts.WalletEvent
	a accounts.Account
}

// Tests that wallet notifications and correctly fired when accounts are added or deleted from the keystore.
// 测试在密钥库中添加或删除帐户时钱包通知是否正确触发。
func TestWalletNotifications(t *testing.T) {
	t.Parallel()
	_, ks := tmpKeyStore(t)

	// Subscribe to the wallet feed and collect events.
	// 订阅钱包源并收集事件。
	var (
		events  []walletEvent
		updates = make(chan accounts.WalletEvent)
		sub     = ks.Subscribe(updates)
	)
	defer sub.Unsubscribe()
	go func() {
		for {
			select {
			case ev := <-updates:
				events = append(events, walletEvent{ev, ev.Wallet.Accounts()[0]})
			case <-sub.Err():
				close(updates)
				return
			}
		}
	}()

	// Randomly add and remove accounts.
	// 随机添加和删除帐户。
	var (
		live       = make(map[common.Address]accounts.Account)
		wantEvents []walletEvent
	)
	for i := 0; i < 1024; i++ {
		if create := len(live) == 0 || rand.Int()%4 > 0; create {
			// Add a new account and ensure wallet notifications arrives
			// 添加新帐户并确保钱包通知到达
			account, err := ks.NewAccount("")
			if err != nil {
				t.Fatalf("failed to create test account: %v", err)
			}
			live[account.Address] = account
			wantEvents = append(wantEvents, walletEvent{accounts.WalletEvent{Kind: accounts.WalletArrived}, account})
		} else {
			// Delete a random account.
			// 删除随机帐户。
			var account accounts.Account
			for _, a := range live {
				account = a
				break
			}
			if err := ks.Delete(account, ""); err != nil {
				t.Fatalf("failed to delete test account: %v", err)
			}
			delete(live, account.Address)
			wantEvents = append(wantEvents, walletEvent{accounts.WalletEvent{Kind: accounts.WalletDropped}, account})
		}
	}

	// Shut down the event collector and check events.
	// 关闭事件收集器并检查事件。
	sub.Unsubscribe()
	for ev := range updates {
		events = append(events, walletEvent{ev, ev.Wallet.Accounts()[0]})
	}
	checkAccounts(t, live, ks.Wallets())
	checkEvents(t, wantEvents, events)
}

// TestImportECDSA tests the import functionality of a keystore.
// TestImportECDSA 测试密钥库的导入功能。
func TestImportECDSA(t *testing.T) {
	t.Parallel()
	_, ks := tmpKeyStore(t)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", key)
	}
	if _, err = ks.ImportECDSA(key, "old"); err != nil {
		t.Errorf("importing failed: %v", err)
	}
	if _, err = ks.ImportECDSA(key, "old"); err == nil {
		t.Errorf("importing same key twice succeeded")
	}
	if _, err = ks.ImportECDSA(key, "new"); err == nil {
		t.Errorf("importing same key twice succeeded")
	}
}

// TestImportExport tests the import and export functionality of a keystore.
// TestImportExport 测试密钥库的导入和导出功能。
func TestImportExport(t *testing.T) {
	t.Parallel()
	_, ks := tmpKeyStore(t)
	acc, err := ks.NewAccount("old")
	if err != nil {
		t.Fatalf("failed to create account: %v", acc)
	}
	json, err := ks.Export(acc, "old", "new")
	if err != nil {
		t.Fatalf("failed to export account: %v", acc)
	}
	_, ks2 := tmpKeyStore(t)
	if _, err = ks2.Import(json, "old", "old"); err == nil {
		t.Errorf("importing with invalid password succeeded")
	}
	acc2, err := ks2.Import(json, "new", "new")
	if err != nil {
		t.Errorf("importing failed: %v", err)
	}
	if acc.Address != acc2.Address {
		t.Error("imported account does not match exported account")
	}
	if _, err = ks2.Import(json, "new", "new"); err == nil {
		t.Errorf("importing a key twice succeeded")
	}
}

// TestImportRace tests the keystore on races. This test should fail under -race if importing races.
// TestImportRace 测试竞赛中的密钥库。如果导入竞赛，此测试应该在 -race 下失败。
func TestImportRace(t *testing.T) {
	t.Parallel()
	_, ks := tmpKeyStore(t)
	acc, err := ks.NewAccount("old")
	if err != nil {
		t.Fatalf("failed to create account: %v", acc)
	}
	json, err := ks.Export(acc, "old", "new")
	if err != nil {
		t.Fatalf("failed to export account: %v", acc)
	}
	_, ks2 := tmpKeyStore(t)
	var atom atomic.Uint32
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			if _, err := ks2.Import(json, "new", "new"); err != nil {
				atom.Add(1)
			}
		}()
	}
	wg.Wait()
	if atom.Load() != 1 {
		t.Errorf("Import is racy")
	}
}

// checkAccounts checks that all known live accounts are present in the wallet list.
// checkAccounts 检查钱包列表中是否存在所有已知的真实账户。
func checkAccounts(t *testing.T, live map[common.Address]accounts.Account, wallets []accounts.Wallet) {
	if len(live) != len(wallets) {
		t.Errorf("wallet list doesn't match required accounts: have %d, want %d", len(wallets), len(live))
		return
	}
	liveList := make([]accounts.Account, 0, len(live))
	for _, account := range live {
		liveList = append(liveList, account)
	}
	slices.SortFunc(liveList, byURL)
	for j, wallet := range wallets {
		if accs := wallet.Accounts(); len(accs) != 1 {
			t.Errorf("wallet %d: contains invalid number of accounts: have %d, want 1", j, len(accs))
		} else if accs[0] != liveList[j] {
			t.Errorf("wallet %d: account mismatch: have %v, want %v", j, accs[0], liveList[j])
		}
	}
}

// checkEvents checks that all events in 'want' are present in 'have'. Events may be present multiple times.
// checkEvents 检查“want”中的所有事件是否都出现在“have”中。事件可能会出现多次。
func checkEvents(t *testing.T, want []walletEvent, have []walletEvent) {
	for _, wantEv := range want {
		nmatch := 0
		for ; len(have) > 0; nmatch++ {
			if have[0].Kind != wantEv.Kind || have[0].a != wantEv.a {
				break
			}
			have = have[1:]
		}
		if nmatch == 0 {
			t.Fatalf("can't find event with Kind=%v for %x", wantEv.Kind, wantEv.a.Address)
		}
	}
}

func tmpKeyStore(t *testing.T) (string, *KeyStore) {
	d := t.TempDir()
	return d, NewKeyStore(d, veryLightScryptN, veryLightScryptP)
}


