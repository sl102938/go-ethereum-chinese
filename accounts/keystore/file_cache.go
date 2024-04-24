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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ethereum/go-ethereum/log"
)

// fileCache is a cache of files seen during scan of keystore.
// fileCache 是在扫描密钥库期间看到的文件的缓存。
type fileCache struct {
	all     mapset.Set[string] // Set of all files from the keystore folder // 密钥库文件夹中所有文件的集合
	lastMod time.Time          // Last time instance when a file was modified // 上次修改文件的时间
	mu      sync.Mutex
}

// scan performs a new scan on the given directory, compares against the already cached filenames, and returns file sets: creates, deletes, updates.
// scan 对给定目录执行新扫描，与已缓存的文件名进行比较，并返回文件集：创建、删除、更新。
func (fc *fileCache) scan(keyDir string) (mapset.Set[string], mapset.Set[string], mapset.Set[string], error) {
	t0 := time.Now()

	// List all the files from the keystore folder
	// 列出密钥库文件夹中的所有文件
	files, err := os.ReadDir(keyDir)
	if err != nil {
		return nil, nil, nil, err
	}
	t1 := time.Now()

	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Iterate all the files and gather their metadata
	// 迭代所有文件并收集其元数据
	all := mapset.NewThreadUnsafeSet[string]()
	mods := mapset.NewThreadUnsafeSet[string]()

	var newLastMod time.Time
	for _, fi := range files {
		path := filepath.Join(keyDir, fi.Name())
		// Skip any non-key files from the folder
		// 跳过文件夹中的任何非关键文件
		if nonKeyFile(fi) {
			log.Trace("Ignoring file on account scan", "path", path)
			continue
		}
		// Gather the set of all and freshly modified files
		// 收集所有和新修改的文​​件集
		all.Add(path)

		info, err := fi.Info()
		if err != nil {
			return nil, nil, nil, err
		}
		modified := info.ModTime()
		if modified.After(fc.lastMod) {
			mods.Add(path)
		}
		if modified.After(newLastMod) {
			newLastMod = modified
		}
	}
	t2 := time.Now()

	// Update the tracked files and return the three sets
	// 更新跟踪文件并返回三组
	deletes := fc.all.Difference(all)   // Deletes = previous - current // 删除 = 上一个 - 当前
	creates := all.Difference(fc.all)   // Creates = current - previous // 创建 = 当前 - 上一个
	updates := mods.Difference(creates) // Updates = modified - creates // 更新=修改-创建

	fc.all, fc.lastMod = all, newLastMod
	t3 := time.Now()

	// Report on the scanning stats and return
	// 扫描统计报告并返回
	log.Debug("FS scan times", "list", t1.Sub(t0), "set", t2.Sub(t1), "diff", t3.Sub(t2))
	return creates, deletes, updates, nil
}

// nonKeyFile ignores editor backups, hidden files and folders/symlinks.
// nonKeyFile 忽略编辑器备份、隐藏文件和文件夹/符号链接。
func nonKeyFile(fi os.DirEntry) bool {
	// Skip editor backups and UNIX-style hidden files.
	// 跳过编辑器备份和 UNIX 风格的隐藏文件。
	if strings.HasSuffix(fi.Name(), "~") || strings.HasPrefix(fi.Name(), ".") {
		return true
	}
	// Skip misc special files, directories (yes, symlinks too).
	// 跳过其他特殊文件、目录（是的，还有符号链接）。
	if fi.IsDir() || !fi.Type().IsRegular() {
		return true
	}
	return false
}


