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
	"fmt"
	"os"
	"sync"

	"github.com/deepflowio/deepflow/server/libs/datatype"
)

const (
	SNAPLEN = 65535
)

type WriterCounter struct {
	totalBufferedCount uint64
	totalWrittenCount  uint64
	totalBufferedBytes uint64
	totalWrittenBytes  uint64
}

type Writer struct {
	filename string
	fp       *os.File

	buffer     [2][]byte
	bufferSize int
	latch      int
	flushed    *sync.WaitGroup
	offset     int

	fileSize int64

	tcpipChecksum bool

	WriterCounter
}

func NewWriter(filename string, bufferSize int, tcpipChecksum bool) (*Writer, error) {
	writer := &Writer{}
	writer.bufferSize = bufferSize
	writer.buffer[0] = make([]byte, bufferSize)
	writer.buffer[1] = make([]byte, bufferSize)
	writer.flushed = &sync.WaitGroup{}
	writer.tcpipChecksum = tcpipChecksum
	if err := writer.init(filename); err != nil {
		return nil, err
	}
	return writer, nil
}

func (w *Writer) init(filename string) error {
	w.filename = filename
	isNewFile := false
	if stat, err := os.Stat(filename); os.IsNotExist(err) {
		isNewFile = true
	} else if err == nil {
		if stat.Size() == 0 {
			isNewFile = true
		}
	} else {
		return err
	}
	w.offset = 0
	var err error
	if isNewFile {
		if w.fp, err = os.Create(filename); err != nil {
			return err
		}
		NewGlobalHeader(w.buffer[w.latch], SNAPLEN)
		w.offset = GLOBAL_HEADER_LEN
		w.totalBufferedCount++
		w.totalBufferedBytes += GLOBAL_HEADER_LEN
	} else {
		if w.fp, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) Write(packet *datatype.MetaPacket) error {
	maxPacketSize := RECORD_HEADER_LEN + MAX_HEADER_LEN
	if packet.RawHeaderSize > 0 {
		maxPacketSize = RECORD_HEADER_LEN + int(packet.RawHeaderSize)
	}
	if w.bufferSize-w.offset < maxPacketSize {
		if err := w.Flush(); err != nil {
			return err
		}
	}

	header := NewRecordHeader(w.buffer[w.latch][w.offset:])
	w.offset += RECORD_HEADER_LEN
	size := NewRawPacket(w.buffer[w.latch][w.offset:]).MetaPacketToRaw(packet, w.tcpipChecksum)
	w.offset += size
	header.SetTimestamp(packet.Timestamp)
	header.SetOrigLen(int(packet.PacketLen))
	header.SetInclLen(size)
	w.totalBufferedCount++
	w.totalBufferedBytes += uint64(RECORD_HEADER_LEN + size)
	return nil
}

func (w *Writer) BufferSize() int {
	return w.offset
}

func (w *Writer) FileSize() int64 {
	return w.fileSize
}

func (w *Writer) GetStats() WriterCounter {
	return w.WriterCounter
}

func (w *Writer) ResetStats() {
	w.totalBufferedCount = 0
	w.totalWrittenCount = 0
	w.totalBufferedBytes = 0
	w.totalWrittenBytes = 0
}

func (w *Writer) GetAndResetStats() WriterCounter {
	c := w.GetStats()
	w.ResetStats()
	return c
}

func (w *Writer) Close() error {
	if w.offset != 0 {
		if err := w.Flush(); err != nil {
			return err
		}
		w.flushed.Wait()
	}
	return w.fp.Close()
}

func (w *Writer) Clear() {
	w.offset = 0
}

func (w *Writer) backgroundFlush(latch, size int) error {
	defer w.flushed.Done()
	if n, err := w.fp.Write(w.buffer[latch][:size]); err != nil {
		return err
	} else {
		w.fileSize += int64(n)
		w.totalWrittenCount++
		w.totalWrittenBytes += uint64(n)
		if n != size {
			return fmt.Errorf("Flush(): not all bytes written to file %s", w.filename)
		}
	}
	return nil
}

func (w *Writer) Flush() error {
	w.flushed.Wait()
	if w.offset == 0 {
		return nil
	}
	w.flushed.Add(1)
	go w.backgroundFlush(w.latch, w.offset)
	w.latch = 1 - w.latch
	w.Clear()
	return nil
}
