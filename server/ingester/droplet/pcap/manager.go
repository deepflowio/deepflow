/*
 * Copyright (c) 2024 Yunshan Networks
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
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
)

var (
	EXAMPLE_TEMPNAME        = getTempFilename(zerodoc.CLOUD, 0, time.Duration(time.Now().UnixNano()), 0)
	EXAMPLE_TEMPNAME_SPLITS = len(strings.Split(EXAMPLE_TEMPNAME, "_"))
)

type WorkerManager struct {
	packetQueueReaders []queue.QueueReader
	packetQueueWriters []queue.QueueWriter
	workers            []*Worker

	tcpipChecksum         bool
	blockSizeKB           int
	maxConcurrentFiles    int
	maxFileSizeMB         int
	maxFilePeriodSecond   int
	maxDirectorySizeGB    int
	diskFreeSpaceMarginGB int
	baseDirectory         string
}

func NewWorkerManager(
	packetQueueReaders []queue.QueueReader,
	packetQueueWriters []queue.QueueWriter,
	tcpipChecksum bool,
	blockSizeKB int,
	maxConcurrentFiles int,
	maxFileSizeMB int,
	maxFilePeriodSecond int,
	maxDirectorySizeGB int,
	diskFreeSpaceMarginGB int,
	baseDirectory string,
) *WorkerManager {
	return &WorkerManager{
		packetQueueReaders: packetQueueReaders,
		packetQueueWriters: packetQueueWriters,
		workers:            make([]*Worker, len(packetQueueReaders)),

		tcpipChecksum:         tcpipChecksum,
		blockSizeKB:           blockSizeKB,
		maxConcurrentFiles:    maxConcurrentFiles,
		maxFileSizeMB:         maxFileSizeMB,
		maxFilePeriodSecond:   maxFilePeriodSecond,
		maxDirectorySizeGB:    maxDirectorySizeGB,
		diskFreeSpaceMarginGB: diskFreeSpaceMarginGB,
		baseDirectory:         baseDirectory,
	}
}

func (m *WorkerManager) Start() []io.Closer {
	os.MkdirAll(m.baseDirectory, os.ModePerm)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go markAndCleanTempFiles(m.baseDirectory, wg)
	wg.Wait()

	for i := 0; i < len(m.packetQueueReaders); i++ {
		worker := m.newWorker(queue.HashKey(i))
		m.workers[i] = worker
		common.RegisterCountableForIngester("pcap", worker, stats.OptionStatTags{"index": strconv.Itoa(i)})
		go worker.Process()
	}
	return []io.Closer{m}
}

func (m *WorkerManager) Close() error {
	wg := sync.WaitGroup{}
	wg.Add(len(m.workers))
	for _, w := range m.workers {
		go func(worker *Worker, waitGroup *sync.WaitGroup) {
			worker.Close()
			waitGroup.Done()
		}(w, &wg)
	}
	time.Sleep(time.Second)
	for i := range m.workers {
		// FIXME: 统一用queue发送nil处理所有goroutine的结束，以避免持有QueueWriter
		// tick the workers
		m.packetQueueWriters[i].Put(nil)
	}
	wg.Wait()
	return nil
}

func findLastRecordTime(file string) time.Duration {
	fp, err := os.Open(file)
	if err != nil {
		log.Debugf("Open %s failed: %s", file, err)
		return 0
	}
	defer fp.Close()

	if info, err := fp.Stat(); err != nil || info.Size() <= GLOBAL_HEADER_LEN+RECORD_HEADER_LEN {
		log.Debugf("Invalid content in file %s", file)
		return 0
	}

	buffer := make([]byte, RECORD_HEADER_LEN)
	lastRecordTime := uint32(0)

	fp.Seek(GLOBAL_HEADER_LEN, io.SeekStart)
	for {
		if n, err := fp.Read(buffer); err != nil || n != RECORD_HEADER_LEN {
			break
		}
		second := binary.LittleEndian.Uint32(buffer[TS_SEC_OFFSET:])
		length := binary.LittleEndian.Uint32(buffer[INCL_LEN_OFFSET:])
		if second > lastRecordTime {
			lastRecordTime = second
		}
		fp.Seek(int64(length), io.SeekCurrent)
	}

	return time.Duration(lastRecordTime) * time.Second
}

func isTempFilename(name string) bool {
	return strings.HasSuffix(name, ".pcap.temp") && len(strings.Split(name, "_")) == EXAMPLE_TEMPNAME_SPLITS
}

func markAndCleanTempFiles(baseDirectory string, scanWg *sync.WaitGroup) {
	var files []string
	filepath.Walk(baseDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name := info.Name()
		if info.IsDir() || !isTempFilename(name) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	scanWg.Done()

	// finish files gracefully
	for _, path := range files {
		lastPacketTime := findLastRecordTime(path)
		if lastPacketTime == 0 {
			log.Debugf("Remove empty or corrupted file %s", path)
			os.Remove(path)
			continue
		}
		firstDotIndex := strings.IndexByte(path, '.')
		newFilename := path[:firstDotIndex] + formatDuration(lastPacketTime) + path[firstDotIndex:strings.Index(path, ".temp")]
		os.Rename(path, newFilename)
	}
}
