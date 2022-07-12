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
	"encoding/binary"
	"time"

	"github.com/google/gopacket/layers"
)

const (
	GLOBAL_HEADER_LEN = 24
	PCAP_MAGIC        = 0xa1b2c3d4
	VERSION_MAJOR     = 2
	VERSION_MINOR     = 4
)

type GlobalHeader []byte

func NewGlobalHeader(buffer []byte, snaplen uint32) GlobalHeader {
	offset := 0
	// magic_number 4B
	binary.LittleEndian.PutUint32(buffer[offset:], PCAP_MAGIC)
	offset += 4
	// version_major 2B
	binary.LittleEndian.PutUint16(buffer[offset:], VERSION_MAJOR)
	offset += 2
	// version_minor 2B
	binary.LittleEndian.PutUint16(buffer[offset:], VERSION_MINOR)
	offset += 2
	// thiszone 4B and sigfigs 4B
	offset += 8
	// snaplen 4B
	binary.LittleEndian.PutUint32(buffer[offset:], snaplen)
	offset += 4
	// network 4B
	binary.LittleEndian.PutUint32(buffer[offset:], uint32(layers.LinkTypeEthernet))
	return buffer
}

const (
	RECORD_HEADER_LEN = 16
	TS_SEC_OFFSET     = 0
	TS_USEC_OFFSET    = 4
	INCL_LEN_OFFSET   = 8
	ORIG_LEN_OFFSET   = 12
)

type RecordHeader []byte

func NewRecordHeader(buffer []byte) RecordHeader {
	return buffer
}

func (h RecordHeader) SetTimestamp(ts time.Duration) {
	sec := ts / time.Second
	usec := (ts - sec*time.Second) / time.Microsecond
	binary.LittleEndian.PutUint32(h[TS_SEC_OFFSET:], uint32(sec))
	binary.LittleEndian.PutUint32(h[TS_USEC_OFFSET:], uint32(usec))
}

func (h RecordHeader) SetInclLen(inclLen int) {
	binary.LittleEndian.PutUint32(h[INCL_LEN_OFFSET:], uint32(inclLen))
}

func (h RecordHeader) SetOrigLen(origLen int) {
	binary.LittleEndian.PutUint32(h[ORIG_LEN_OFFSET:], uint32(origLen))
}
