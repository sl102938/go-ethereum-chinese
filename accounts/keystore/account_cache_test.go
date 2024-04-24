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
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cespare/cp"
	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
)

var (
	cachetestDir, _   = filepath.Abs(filepath.Join("testdata", "keystore"))
	cachetestAccounts = []accounts.Account{
		{
			Address: common.HexToAddress("7ef5a6135f1fd6a02593eedc869c6d41d934aef8"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: filepath.Join(cachetestDir, "UTC--2016-03-22T12-57-55.920751759Z--7ef5a6135f1fd6a02593eedc869c6d41d934aef8")},
		},
		{
			Address: common.HexToAddress("f466859ead1932d743d622cb74fc058882e8648a"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: filepath.Join(cachetestDir, "aaa")},
		},
		{
			Address: common.HexToAddress("289d485d9771714cce91d3393d764e1311907acc"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: filepath.Join(cachetestDir, "zzz")},
		},
	}
)

// waitWatcherStart waits up to 1s for the keystore watcher to start.
// waitWatcherStart 等待密钥库观察程序启动最多 1 秒。
func waitWatcherStart(ks *KeyStore) bool {
	// On systems where file watch is not supported, just return "ok".
	// 在不支持文件监视的系统上，只需返回“ok”即可。
	if !ks.cache.watcher.enabled() {
		return true
	}
	// The watcher should start, and then exit.
	// 观察者应该启动，然后退出。
	for t0 := time.Now(); time.Since(t0) < 1*time.Second; time.Sleep(100 * time.Millisecond) {
		if ks.cache.watcherStarted() {
			return true
		}
	}
	return false
}

func waitForAccounts(wantAccounts []accounts.Account, ks *KeyStore) error {
	var list []accounts.Account
	for t0 := time.Now(); time.Since(t0) < 5*time.Second; time.Sleep(100 * time.Millisecond) {
		list = ks.Accounts()
		if reflect.DeepEqual(list, wantAccounts) {
			// ks should have also received change notifications
			// ks 应该也收到了变更通知
			select {
			case <-ks.changes:
			default:
				return errors.New("wasn't notified of new accounts")
			}
			return nil
		}
	}
	return fmt.Errorf("\ngot  %v\nwant %v", list, wantAccounts)
}

func TestWatchNewFile(t *testing.T) {
	t.Parallel()

	dir, ks := tmpKeyStore(t)

	// Ensure the watcher is started before adding any files.
	// 在添加任何文件之前确保观察程序已启动。
	ks.Accounts()
	if !waitWatcherStart(ks) {
		t.Fatal("keystore watcher didn't start in time")
	}
	// Move in the files.
	// 移入文件。
	wantAccounts := make([]accounts.Account, len(cachetestAccounts))
	for i := range cachetestAccounts {
		wantAccounts[i] = accounts.Account{
			Address: cachetestAccounts[i].Address,
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: filepath.Join(dir, filepath.Base(cachetestAccounts[i].URL.Path))},
		}
		if err := cp.CopyFile(wantAccounts[i].URL.Path, cachetestAccounts[i].URL.Path); err != nil {
			t.Fatal(err)
		}
	}

	// ks should see the accounts.
	// ks 应该看到账户。
	if err := waitForAccounts(wantAccounts, ks); err != nil {
		t.Error(err)
	}
}

func TestWatchNoDir(t *testing.T) {
	t.Parallel()
	// Create ks but not the directory that it watches.
	// 创建 ks 但不创建它监视的目录。
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("eth-keystore-watchnodir-test-%d-%d", os.Getpid(), rand.Int()))
	ks := NewKeyStore(dir, LightScryptN, LightScryptP)
	list := ks.Accounts()
	if len(list) > 0 {
		t.Error("initial account list not empty:", list)
	}
	// The watcher should start, and then exit.
	// 观察者应该启动，然后退出。
	if !waitWatcherStart(ks) {
		t.Fatal("keystore watcher didn't start in time")
	}
	// Create the directory and copy a key file into it.
	// 创建目录并将密钥文件复制到其中。
	os.MkdirAll(dir, 0700)
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "aaa")
	if err := cp.CopyFile(file, cachetestAccounts[0].URL.Path); err != nil {
		t.Fatal(err)
	}

	// ks should see the account.
	// ks 应该可以看到该帐户。
	wantAccounts := []accounts.Account{cachetestAccounts[0]}
	wantAccounts[0].URL = accounts.URL{Scheme: KeyStoreScheme, Path: file}
	for d := 200 * time.Millisecond; d < 8*time.Second; d *= 2 {
		list = ks.Accounts()
		if reflect.DeepEqual(list, wantAccounts) {
			// ks should have also received change notifications
			// ks 应该也收到了变更通知
			select {
			case <-ks.changes:
			default:
				t.Fatalf("wasn't notified of new accounts")
			}
			return
		}
		time.Sleep(d)
	}
	t.Errorf("\ngot  %v\nwant %v", list, wantAccounts)
}

func TestCacheInitialReload(t *testing.T) {
	t.Parallel()
	cache, _ := newAccountCache(cachetestDir)
	accounts := cache.accounts()
	if !reflect.DeepEqual(accounts, cachetestAccounts) {
		t.Fatalf("got initial accounts: %swant %s", spew.Sdump(accounts), spew.Sdump(cachetestAccounts))
	}
}

func TestCacheAddDeleteOrder(t *testing.T) {
	t.Parallel()
	cache, _ := newAccountCache("testdata/no-such-dir")
	cache.watcher.running = true // prevent unexpected reloads // 防止意外重新加载

	accs := []accounts.Account{
		{
			Address: common.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: "-309830980"},
		},
		{
			Address: common.HexToAddress("2cac1adea150210703ba75ed097ddfe24e14f213"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: "ggg"},
		},
		{
			Address: common.HexToAddress("8bda78331c916a08481428e4b07c96d3e916d165"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: "zzzzzz-the-very-last-one.keyXXX"},
		},
		{
			Address: common.HexToAddress("d49ff4eeb0b2686ed89c0fc0f2b6ea533ddbbd5e"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: "SOMETHING.key"},
		},
		{
			Address: common.HexToAddress("7ef5a6135f1fd6a02593eedc869c6d41d934aef8"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: "UTC--2016-03-22T12-57-55.920751759Z--7ef5a6135f1fd6a02593eedc869c6d41d934aef8"},
		},
		{
			Address: common.HexToAddress("f466859ead1932d743d622cb74fc058882e8648a"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: "aaa"},
		},
		{
			Address: common.HexToAddress("289d485d9771714cce91d3393d764e1311907acc"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: "zzz"},
		},
	}
	for _, a := range accs {
		cache.add(a)
	}
	// Add some of them twice to check that they don't get reinserted.
	// 将其中一些添加两次以检查它们是否不会被重新插入。
	cache.add(accs[0])
	cache.add(accs[2])

	// Check that the account list is sorted by filename.
	// 检查帐户列表是否按文件名排序。
	wantAccounts := make([]accounts.Account, len(accs))
	copy(wantAccounts, accs)
	slices.SortFunc(wantAccounts, byURL)
	list := cache.accounts()
	if !reflect.DeepEqual(list, wantAccounts) {
		t.Fatalf("got accounts: %s\nwant %s", spew.Sdump(accs), spew.Sdump(wantAccounts))
	}
	for _, a := range accs {
		if !cache.hasAddress(a.Address) {
			t.Errorf("expected hasAccount(%x) to return true", a.Address)
		}
	}
	if cache.hasAddress(common.HexToAddress("fd9bd350f08ee3c0c19b85a8e16114a11a60aa4e")) {
		t.Errorf("expected hasAccount(%x) to return false", common.HexToAddress("fd9bd350f08ee3c0c19b85a8e16114a11a60aa4e"))
	}

	// Delete a few keys from the cache.
	// 从缓存中删除一些键。
	for i := 0; i < len(accs); i += 2 {
		cache.delete(wantAccounts[i])
	}
	cache.delete(accounts.Account{Address: common.HexToAddress("fd9bd350f08ee3c0c19b85a8e16114a11a60aa4e"), URL: accounts.URL{Scheme: KeyStoreScheme, Path: "something"}})

	// Check content again after deletion.
	// 删除后再次检查内容。
	wantAccountsAfterDelete := []accounts.Account{
		wantAccounts[1],
		wantAccounts[3],
		wantAccounts[5],
	}
	list = cache.accounts()
	if !reflect.DeepEqual(list, wantAccountsAfterDelete) {
		t.Fatalf("got accounts after delete: %s\nwant %s", spew.Sdump(list), spew.Sdump(wantAccountsAfterDelete))
	}
	for _, a := range wantAccountsAfterDelete {
		if !cache.hasAddress(a.Address) {
			t.Errorf("expected hasAccount(%x) to return true", a.Address)
		}
	}
	if cache.hasAddress(wantAccounts[0].Address) {
		t.Errorf("expected hasAccount(%x) to return false", wantAccounts[0].Address)
	}
}

func TestCacheFind(t *testing.T) {
	t.Parallel()
	dir := filepath.Join("testdata", "dir")
	cache, _ := newAccountCache(dir)
	cache.watcher.running = true // prevent unexpected reloads // 防止意外重新加载

	accs := []accounts.Account{
		{
			Address: common.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: filepath.Join(dir, "a.key")},
		},
		{
			Address: common.HexToAddress("2cac1adea150210703ba75ed097ddfe24e14f213"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: filepath.Join(dir, "b.key")},
		},
		{
			Address: common.HexToAddress("d49ff4eeb0b2686ed89c0fc0f2b6ea533ddbbd5e"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: filepath.Join(dir, "c.key")},
		},
		{
			Address: common.HexToAddress("d49ff4eeb0b2686ed89c0fc0f2b6ea533ddbbd5e"),
			URL:     accounts.URL{Scheme: KeyStoreScheme, Path: filepath.Join(dir, "c2.key")},
		},
	}
	for _, a := range accs {
		cache.add(a)
	}

	nomatchAccount := accounts.Account{
		Address: common.HexToAddress("f466859ead1932d743d622cb74fc058882e8648a"),
		URL:     accounts.URL{Scheme: KeyStoreScheme, Path: filepath.Join(dir, "something")},
	}
	tests := []struct {
		Query      accounts.Account
		WantResult accounts.Account
		WantError  error
	}{
		// by address
		// 按地址
		{Query: accounts.Account{Address: accs[0].Address}, WantResult: accs[0]},
		// by file
		// 按文件
		{Query: accounts.Account{URL: accs[0].URL}, WantResult: accs[0]},
		// by basename
		// 按基本名称
		{Query: accounts.Account{URL: accounts.URL{Scheme: KeyStoreScheme, Path: filepath.Base(accs[0].URL.Path)}}, WantResult: accs[0]},
		// by file and address
		// 按文件和地址
		{Query: accs[0], WantResult: accs[0]},
		// ambiguous address, tie resolved by file
		// 地址不明确，由文件解决
		{Query: accs[2], WantResult: accs[2]},
		// ambiguous address error
		// 不明确的地址错误
		{
			Query: accounts.Account{Address: accs[2].Address},
			WantError: &AmbiguousAddrError{
				Addr:    accs[2].Address,
				Matches: []accounts.Account{accs[2], accs[3]},
			},
		},
		// no match error
		// 无匹配错误
		{Query: nomatchAccount, WantError: ErrNoMatch},
		{Query: accounts.Account{URL: nomatchAccount.URL}, WantError: ErrNoMatch},
		{Query: accounts.Account{URL: accounts.URL{Scheme: KeyStoreScheme, Path: filepath.Base(nomatchAccount.URL.Path)}}, WantError: ErrNoMatch},
		{Query: accounts.Account{Address: nomatchAccount.Address}, WantError: ErrNoMatch},
	}
	for i, test := range tests {
		a, err := cache.find(test.Query)
		if !reflect.DeepEqual(err, test.WantError) {
			t.Errorf("test %d: error mismatch for query %v\ngot %q\nwant %q", i, test.Query, err, test.WantError)
			continue
		}
		if a != test.WantResult {
			t.Errorf("test %d: result mismatch for query %v\ngot %v\nwant %v", i, test.Query, a, test.WantResult)
			continue
		}
	}
}

// TestUpdatedKeyfileContents tests that updating the contents of a keystore file is noticed by the watcher, and the account cache is updated accordingly
// TestUpdatedKeyfileContents 测试观察者注意到更新密钥库文件的内容，并相应更新帐户缓存
func TestUpdatedKeyfileContents(t *testing.T) {
	t.Parallel()

	// Create a temporary keystore to test with
	// 创建一个临时密钥库进行测试
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("eth-keystore-updatedkeyfilecontents-test-%d-%d", os.Getpid(), rand.Int()))
	ks := NewKeyStore(dir, LightScryptN, LightScryptP)

	list := ks.Accounts()
	if len(list) > 0 {
		t.Error("initial account list not empty:", list)
	}
	if !waitWatcherStart(ks) {
		t.Fatal("keystore watcher didn't start in time")
	}
	// Create the directory and copy a key file into it.
	// 创建目录并将密钥文件复制到其中。
	os.MkdirAll(dir, 0700)
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "aaa")

	// Place one of our testfiles in there
	// 将我们的测试文件之一放入其中
	if err := cp.CopyFile(file, cachetestAccounts[0].URL.Path); err != nil {
		t.Fatal(err)
	}

	// ks should see the account.
	// ks 应该可以看到该帐户。
	wantAccounts := []accounts.Account{cachetestAccounts[0]}
	wantAccounts[0].URL = accounts.URL{Scheme: KeyStoreScheme, Path: file}
	if err := waitForAccounts(wantAccounts, ks); err != nil {
		t.Error(err)
		return
	}
	// needed so that modTime of `file` is different to its current value after forceCopyFile
	// 需要使`file`的modTime不同于forceCopyFile之后的当前值
	os.Chtimes(file, time.Now().Add(-time.Second), time.Now().Add(-time.Second))

	// Now replace file contents
	// 现在替换文件内容
	if err := forceCopyFile(file, cachetestAccounts[1].URL.Path); err != nil {
		t.Fatal(err)
		return
	}
	wantAccounts = []accounts.Account{cachetestAccounts[1]}
	wantAccounts[0].URL = accounts.URL{Scheme: KeyStoreScheme, Path: file}
	if err := waitForAccounts(wantAccounts, ks); err != nil {
		t.Errorf("First replacement failed")
		t.Error(err)
		return
	}

	// needed so that modTime of `file` is different to its current value after forceCopyFile
	// 需要使`file`的modTime不同于forceCopyFile之后的当前值
	os.Chtimes(file, time.Now().Add(-time.Second), time.Now().Add(-time.Second))

	// Now replace file contents again
	// 现在再次替换文件内容
	if err := forceCopyFile(file, cachetestAccounts[2].URL.Path); err != nil {
		t.Fatal(err)
		return
	}
	wantAccounts = []accounts.Account{cachetestAccounts[2]}
	wantAccounts[0].URL = accounts.URL{Scheme: KeyStoreScheme, Path: file}
	if err := waitForAccounts(wantAccounts, ks); err != nil {
		t.Errorf("Second replacement failed")
		t.Error(err)
		return
	}

	// needed so that modTime of `file` is different to its current value after os.WriteFile
	// 需要这样，以便 `file` 的 modTime 与 os.WriteFile 之后的当前值不同
	os.Chtimes(file, time.Now().Add(-time.Second), time.Now().Add(-time.Second))

	// Now replace file contents with crap
	// 现在用垃圾替换文件内容
	if err := os.WriteFile(file, []byte("foo"), 0600); err != nil {
		t.Fatal(err)
		return
	}
	if err := waitForAccounts([]accounts.Account{}, ks); err != nil {
		t.Errorf("Emptying account file failed")
		t.Error(err)
		return
	}
}

// forceCopyFile is like cp.CopyFile, but doesn't complain if the destination exists.
// forceCopyFile 类似于 cp.CopyFile，但如果目标存在则不会抱怨。
func forceCopyFile(dst, src string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}


