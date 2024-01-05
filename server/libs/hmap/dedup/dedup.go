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

package dedup

import (
	. "encoding/binary"
	"time"

	"github.com/OneOfOne/xxhash"
	. "github.com/google/gopacket/layers"
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/libs/stats"
)

var log = logging.MustGetLogger("dedup")

func (m *PacketDedupMap) hashPacket(packet []byte) {
	m.lookupNode = blankPacketDedupMapNodeForInit
	m.lookupNode.keySize = PACKET_ID_SIZE_V4
	packetId := m.lookupNode.key[:]

	if len(packet) < 18 { // ensure safety
		copy(packetId, packet)
		m.lookupNode.hash = xxhash.Checksum32(packetId)
		return
	}
	copy(packetId[:12], packet[:12])

	ethType := EthernetType(BigEndian.Uint16(packet[12:]))
	if ethType == EthernetTypeDot1Q {
		ethType = EthernetType(BigEndian.Uint16(packet[16:]))
		if ethType == EthernetTypeDot1Q {
			ethType = EthernetType(BigEndian.Uint16(packet[20:]))
			// 仅虚拟网络需要做dedup，且虚拟网络QinQ外层VLAN肯定是一致的，两层VLAN均忽略
			packet = packet[8:]
		} else {
			// 忽略仅有的一层VLAN
			packet = packet[4:]
		}
	}

	if ethType == EthernetTypeIPv6 {
		m.lookupNode.keySize = PACKET_ID_SIZE_V6
		copy(packetId[12:], packet[12:])

		if m.ignoreTTL {
			packetId[21] = 128
		}
		m.lookupNode.id = uint64(BigEndian.Uint32(packetId[16:20])) | (uint64(packetId[20]) << 32) // Flow Label, Payload Length, Next header
		nextHeader := IPProtocol(packetId[20])
		offset := uint32(0)
		for nextHeader != IPProtocolTCP && nextHeader != IPProtocolUDP && 54+offset+8 <= PACKET_ID_SIZE_V6 {
			nextHeader = IPProtocol(packetId[54+offset])
			offset += uint32(packetId[54+offset+1]) + 8 // 注意：假定这个字节均表示Header Ext Length
		}
		if nextHeader == IPProtocolUDP && 54+offset+8 <= PACKET_ID_SIZE_V6 {
			BigEndian.PutUint16(packetId[54+offset+6:], 0) // ignore L4 checksum
		} else if nextHeader == IPProtocolTCP && 54+offset+20 <= PACKET_ID_SIZE_V6 {
			BigEndian.PutUint16(packetId[54+offset+16:], 0) // ignore L4 checksum
		}
	} else if ethType == EthernetTypeIPv4 {
		packetId = packetId[:m.lookupNode.keySize]
		copy(packetId[12:], packet[12:])

		if m.ignoreTTL {
			packetId[22] = 128
		}
		m.lookupNode.id = uint64(BigEndian.Uint32(packetId[18:22])) | // IP ID, Frag
			(uint64(BigEndian.Uint16(packetId[24:26])) << 32) | // IP checksum
			(uint64(BigEndian.Uint16(packetId[16:18])) << 48) // IP total length
		ihl := int(packetId[14]&0xF) * 4
		ipProtocol := IPProtocol(packetId[23])
		if ipProtocol == IPProtocolUDP && 14+ihl+8 <= PACKET_ID_SIZE_V4 {
			BigEndian.PutUint16(packetId[14+ihl+6:], 0) // ignore L4 checksum
		} else if ipProtocol == IPProtocolTCP && 14+ihl+20 <= PACKET_ID_SIZE_V4 {
			BigEndian.PutUint16(packetId[14+ihl+16:], 0) // ignore L4 checksum
		}
	} else {
		packetId = packetId[:m.lookupNode.keySize]
		copy(packetId[12:], packet[12:])
	}

	m.lookupNode.hash = xxhash.Checksum32(packetId[:m.lookupNode.keySize])
}

func (m *PacketDedupMap) IsDuplicate(packet []byte, timestamp time.Duration) bool {
	m.hashPacket(packet)
	m.lookupNode.timestamp = timestamp
	return m.lookup()
}

func NewPacketDedupMap(name string) *PacketDedupMap {
	m := &PacketDedupMap{
		ringBuffer: make([]packetDedupMapNodeBlock, (ELEMENTS_LIMIT+_BLOCK_SIZE)/_BLOCK_SIZE+1),
		slotHead:   make([]int32, HASH_TABLE_SIZE),
		counter:    &PacketDedupMapCounter{},
	}
	stats.RegisterCountable("dedup", m, stats.OptionStatTags{"name": name})

	for i := 0; i < HASH_TABLE_SIZE; i++ {
		m.slotHead[i] = -1
	}

	return m
}
