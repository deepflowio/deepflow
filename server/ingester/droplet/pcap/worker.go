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
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
)

const (
	QUEUE_BATCH_SIZE = 1024
	BROADCAST_MAC    = datatype.MacInt(^uint64(0) >> 16)
	BROADCAST_IP     = datatype.IPv4Int(^uint32(0))
)

type WriterKey uint64

func getWriterIpv6Key(ip net.IP, aclGID uint16, tapType zerodoc.TAPTypeEnum) WriterKey {
	ipHash := uint32(0)
	for i := 0; i < len(ip); i += 4 {
		ipHash ^= *(*uint32)(unsafe.Pointer(&ip[i]))
	}
	return WriterKey((uint64(ipHash) << 32) | (uint64(aclGID) << 16) | uint64(tapType))
}

func getWriterKey(tapPort uint32, vtapId, aclGID uint16) WriterKey {
	return WriterKey((uint64(tapPort) << 32) | (uint64(aclGID) << 16) | uint64(aclGID))
}

type WrappedWriter struct {
	*Writer

	tempFilename    string
	firstPacketTime time.Duration
	lastPacketTime  time.Duration

	tapPort uint32
	aclGID  uint16
	vtapId  uint16
	tapType zerodoc.TAPTypeEnum
}

type WorkerCounter struct {
	FileCreations        uint64 `statsd:"file_creations"`
	FileCloses           uint64 `statsd:"file_closes"`
	FileRejections       uint64 `statsd:"file_rejections"`
	FileCreationFailures uint64 `statsd:"file_creation_failures"`
	FileWritingFailures  uint64 `statsd:"file_writing_failures"`
	BufferedCount        uint64 `statsd:"buffered_count"`
	WrittenCount         uint64 `statsd:"written_count"`
	BufferedBytes        uint64 `statsd:"buffered_bytes"`
	WrittenBytes         uint64 `statsd:"written_bytes"`
}

type Worker struct {
	packetQueue queue.QueueReader
	index       int

	maxConcurrentFiles int
	maxFileSize        int64
	maxFilePeriod      time.Duration
	baseDirectory      string

	*WorkerCounter

	writers [datatype.TAP_MAX]map[WriterKey]*WrappedWriter

	writerBufferSize int
	tcpipChecksum    bool

	exiting bool
	exited  bool
	exitWg  *sync.WaitGroup
}

func (m *WorkerManager) newWorker(packetQueueID queue.HashKey) *Worker {
	return &Worker{
		packetQueue: m.packetQueueReaders[packetQueueID],
		index:       int(packetQueueID),

		maxConcurrentFiles: m.maxConcurrentFiles / len(m.packetQueueReaders),
		maxFileSize:        int64(m.maxFileSizeMB) << 20,
		maxFilePeriod:      time.Duration(m.maxFilePeriodSecond) * time.Second,
		baseDirectory:      m.baseDirectory,

		WorkerCounter: &WorkerCounter{},

		writerBufferSize: m.blockSizeKB << 10,
		tcpipChecksum:    m.tcpipChecksum,

		exiting: false,
		exited:  false,
		exitWg:  &sync.WaitGroup{},
	}
}

func tapPortToMacString(tapPort uint32) string {
	return fmt.Sprintf("%012x", tapPort)
}

func tapTypeToString(tapType zerodoc.TAPTypeEnum) string {
	if tapType == 3 {
		return "tor"
	}
	return fmt.Sprintf("isp%d", tapType)
}

func formatDuration(d time.Duration) string {
	return time.Unix(0, int64(d)).Format(TIME_FORMAT)
}

func getTempFilename(tapType zerodoc.TAPTypeEnum, tapPort uint32, firstPacketTime time.Duration, index uint16) string {
	return fmt.Sprintf("%s_%s_0_%s_.%d.pcap.temp", tapTypeToString(tapType), tapPortToMacString(tapPort), formatDuration(firstPacketTime), index)
}

func (w *WrappedWriter) getTempFilename(base string) string {
	return fmt.Sprintf("%s/%d/%s", base, w.aclGID, getTempFilename(w.tapType, w.tapPort, w.firstPacketTime, w.vtapId))
}

func (w *WrappedWriter) getFilename(base string) string {
	return fmt.Sprintf("%s/%d/%s_%s_0_%s_%s.%d.pcap", base, w.aclGID, tapTypeToString(w.tapType), tapPortToMacString(w.tapPort), formatDuration(w.firstPacketTime), formatDuration(w.lastPacketTime), w.vtapId)
}

func (w *Worker) shouldCloseFile(writer *WrappedWriter, packet *datatype.MetaPacket) bool {
	// check for file size and time
	if packet.Timestamp-writer.firstPacketTime > time.Second && writer.FileSize()+int64(writer.BufferSize()) >= w.maxFileSize {
		// 距离第一个包时长超过1秒, 且大小超过maxFileSize, 则切换pcap文件
		return true
	}
	if packet.Timestamp-writer.firstPacketTime > w.maxFilePeriod {
		return true
	}
	return false
}

func (w *Worker) finishWriter(writer *WrappedWriter, newFilename string) {
	writer.Close()
	counter := writer.GetAndResetStats()
	w.BufferedCount += counter.totalBufferedCount
	w.WrittenCount += counter.totalWrittenCount
	w.BufferedBytes += counter.totalBufferedBytes
	w.WrittenBytes += counter.totalWrittenBytes
	log.Debugf("Finish writing %s, renaming to %s", writer.tempFilename, newFilename)
	os.Rename(writer.tempFilename, newFilename)
	w.FileCloses++
}

func (w *Worker) writePacket(packet *datatype.MetaPacket, tapType zerodoc.TAPTypeEnum, aclGID uint16) {
	if w.writers[tapType] == nil {
		w.writers[tapType] = make(map[WriterKey]*WrappedWriter)
	}
	key := getWriterKey(packet.TapPort, packet.VtapId, aclGID)
	writer, exist := w.writers[tapType][key]
	if exist && w.shouldCloseFile(writer, packet) {
		newFilename := writer.getFilename(w.baseDirectory)
		w.finishWriter(writer, newFilename)
		delete(w.writers[tapType], key)
		exist = false
	}
	if !exist {
		writer = w.generateWrappedWriter(tapType, aclGID, packet)
		if writer == nil {
			return
		}
		w.writers[tapType][key] = writer
	}
	if err := writer.Write(packet); err != nil {
		log.Debugf("Failed to write packet to %s: %s", writer.tempFilename, err)
		w.FileWritingFailures++
		return
	}
	counter := writer.GetAndResetStats()
	w.BufferedCount += counter.totalBufferedCount
	w.WrittenCount += counter.totalWrittenCount
	w.BufferedBytes += counter.totalBufferedBytes
	w.WrittenBytes += counter.totalWrittenBytes
	writer.lastPacketTime = packet.Timestamp
}

func (w *Worker) generateWrappedWriter(tapType zerodoc.TAPTypeEnum, aclGID uint16, packet *datatype.MetaPacket) *WrappedWriter {
	if len(w.writers) >= w.maxConcurrentFiles {
		if log.IsEnabledFor(logging.DEBUG) {
			log.Debugf("Max concurrent file (%d files) exceeded", w.maxConcurrentFiles)
		}
		w.FileRejections++
		return nil
	}

	directory := fmt.Sprintf("%s/%d", w.baseDirectory, aclGID)
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		os.MkdirAll(directory, os.ModePerm)
	}
	writer := &WrappedWriter{
		tapType:         tapType,
		aclGID:          aclGID,
		vtapId:          packet.VtapId,
		tapPort:         packet.TapPort,
		firstPacketTime: packet.Timestamp,
		lastPacketTime:  packet.Timestamp,
	}

	writer.tempFilename = writer.getTempFilename(w.baseDirectory)
	if log.IsEnabledFor(logging.DEBUG) {
		log.Debugf("Begin to write packets to %s", writer.tempFilename)
	}
	var err error
	if writer.Writer, err = NewWriter(writer.tempFilename, w.writerBufferSize, w.tcpipChecksum); err != nil {
		if log.IsEnabledFor(logging.DEBUG) {
			log.Debugf("Failed to create writer for %s: %s", writer.tempFilename, err)
		}
		w.FileCreationFailures++
		return nil
	}
	w.FileCreations++
	return writer
}

func (w *Worker) cleanTimeoutFile(timeNow time.Duration) {
	for i := datatype.TAP_MIN; i < datatype.TAP_MAX; i++ {
		for key, writer := range w.writers[i] {
			if timeNow-writer.firstPacketTime > w.maxFilePeriod {
				newFilename := writer.getFilename(w.baseDirectory)
				w.finishWriter(writer, newFilename)
				delete(w.writers[i], key)
			}
		}
	}
}

func (w *Worker) toZerodocTAPType(packet *datatype.MetaPacket) zerodoc.TAPTypeEnum {
	if packet.TapType != datatype.TAP_CLOUD {
		return zerodoc.TAPTypeEnum(packet.TapType)
	}
	return zerodoc.CLOUD
}

func (w *Worker) Process() {
	elements := make([]interface{}, QUEUE_BATCH_SIZE)

WORKING_LOOP:
	for !w.exiting {
		n := w.packetQueue.Gets(elements)
		timeNow := time.Duration(time.Now().UnixNano())
		for _, e := range elements[:n] {
			if e == nil { // tick
				if w.exiting {
					break WORKING_LOOP
				}
				w.cleanTimeoutFile(timeNow)
				continue
			}

			block := e.(*datatype.MetaPacketBlock)

			for i := uint8(0); i < block.Count; i++ {
				packet := &block.Metas[i]

				if !packet.EndpointData.Valid() { // shouldn't happen
					log.Warningf("drop invalid packet with nil EndpointData %v", packet)
					continue
				}

				tapType := w.toZerodocTAPType(packet)
				for _, policy := range packet.PolicyData.NpbActions {
					// NOTICE: PCAP存储必须满足TunnelType是NPB_TUNNEL_TYPE_PCAP, 因为策略是NPB_TUNNEL_TYPE_PCAP类型，这里的判断去掉了
					if policy.TunnelGid() <= 0 {
						continue
					}
					w.writePacket(packet, tapType, policy.TunnelGid())
				}
			}

			datatype.ReleaseMetaPacketBlock(block)
		}
	}

	for i := datatype.TAP_MIN; i < datatype.TAP_MAX; i++ {
		for _, writer := range w.writers[i] {
			newFilename := writer.getFilename(w.baseDirectory)
			w.finishWriter(writer, newFilename)
		}
	}
	log.Infof("Stopped pcap worker (%d)", w.index)
	w.exitWg.Done()
}

func (w *Worker) Close() error {
	log.Infof("Stop pcap worker (%d) writing to %d files", w.index, len(w.writers))
	w.exitWg.Add(1)
	w.exiting = true
	w.exitWg.Wait()
	w.exited = true
	return nil
}

func (w *Worker) GetCounter() interface{} {
	counter := &WorkerCounter{}
	counter, w.WorkerCounter = w.WorkerCounter, counter
	return counter
}

func (w *Worker) Closed() bool {
	return w.exited
}
