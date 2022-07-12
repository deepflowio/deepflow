//go:build linux
// +build linux

/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pcap

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("pcap")

type File struct {
	location string
	fileTime time.Time
	size     int64
}

type Cleaner struct {
	maxDirectorySize    int64
	diskFreeSpaceMargin int64
	cleanPeriod         time.Duration
	pcapDataRetention   time.Duration
	baseDirectory       string

	fileLock *FileLock
}

func NewCleaner(cleanPeriod time.Duration, maxDirectorySize, diskFreeSpaceMargin int64, baseDirectory string) *Cleaner {
	return &Cleaner{
		maxDirectorySize:    maxDirectorySize,
		diskFreeSpaceMargin: diskFreeSpaceMargin,
		cleanPeriod:         cleanPeriod,
		baseDirectory:       baseDirectory,
		fileLock:            New(baseDirectory),
	}
}

func (c *Cleaner) UpdatePcapDataRetention(pcapDataRetention time.Duration) {
	atomic.StoreInt64((*int64)(&c.pcapDataRetention), int64(pcapDataRetention))
}

func (c *Cleaner) GetPcapDataRetention() time.Duration {
	return time.Duration(atomic.LoadInt64((*int64)(&c.pcapDataRetention)))
}

func (c *Cleaner) work() {
	var files []File
	for now := range time.Tick(c.cleanPeriod) {
		c.fileLock.Lock()
		files = files[:0]
		filepath.Walk(c.baseDirectory, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Debugf("Walk directory error: %s", err)
				// 返回nil，否则Walk()会中止
				return nil
			}
			name := info.Name()
			if info.IsDir() || !strings.HasSuffix(name, ".pcap") {
				return nil
			}
			files = append(files, File{
				location: path,
				fileTime: info.ModTime(),
				size:     info.Size(),
			})
			return nil
		})
		// 用结束写入时间倒排
		sort.Slice(files, func(i, j int) bool { return files[i].fileTime.Sub(files[j].fileTime) > 0 })

		// check delete
		sumSize := int64(0)
		nDeleted := 0
		pcapDataRetention := c.GetPcapDataRetention()
		firstDeleteIndex, lastDeleteIndex := 0, 0
		for i, f := range files {
			sumSize += f.size
			if sumSize >= c.maxDirectorySize || (pcapDataRetention != 0 && now.Sub(f.fileTime) > pcapDataRetention) {
				if nDeleted == 0 {
					firstDeleteIndex = i
				}
				lastDeleteIndex = i
				os.Remove(f.location)
				nDeleted++
			}
		}
		if nDeleted > 0 {
			log.Infof("Pcap total size %d(before deleted), have deleted pcap file count %d, first file name: %s, mod time: %v, size: %d, last file name: %s, mod time: %v, size: %d",
				sumSize, nDeleted,
				files[firstDeleteIndex].location, files[firstDeleteIndex].fileTime, files[firstDeleteIndex].size,
				files[lastDeleteIndex].location, files[lastDeleteIndex].fileTime, files[lastDeleteIndex].size)
		}

		fs := syscall.Statfs_t{}
		err := syscall.Statfs(c.baseDirectory, &fs)
		if err == nil {
			nDeletedForFree := 0
			firstDeleteIndex, lastDeleteIndex = 0, 0
			free := int64(fs.Bfree) * int64(fs.Bsize)
			for i := len(files) - nDeleted - 1; i >= 0 && free < c.diskFreeSpaceMargin; i-- {
				if nDeletedForFree == 0 {
					firstDeleteIndex = i
				}
				lastDeleteIndex = i
				nDeletedForFree++
				os.Remove(files[i].location)
				free += files[i].size
			}
			if nDeletedForFree > 0 {
				log.Infof("Pcap disk free size %d(after deleted), have deleted pcap file count %d, first file name: %s, mod time: %v, size: %d, last file name: %s, mod time: %v, size: %d",
					free, nDeletedForFree,
					files[firstDeleteIndex].location, files[firstDeleteIndex].fileTime, files[firstDeleteIndex].size,
					files[lastDeleteIndex].location, files[lastDeleteIndex].fileTime, files[lastDeleteIndex].size)
			}

		}
		c.fileLock.Unlock()
	}
}

func (c *Cleaner) Start() {
	go c.work()
}
