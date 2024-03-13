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

package flow_metrics

import (
	"strconv"

	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
)

type UsageMeter struct {
	PacketTx uint64 `json:"packet_tx" category:"$metrics" sub:"NPB"`
	PacketRx uint64 `json:"packet_rx" category:"$metrics" sub:"NPB"`
	ByteTx   uint64 `json:"byte_tx" category:"$metrics" sub:"NPB"`
	ByteRx   uint64 `json:"byte_rx" category:"$metrics" sub:"NPB"`
	L3ByteTx uint64 `json:"l3_byte_tx" category:"$metrics" sub:"NPB"`
	L3ByteRx uint64 `json:"l3_byte_rx" category:"$metrics" sub:"NPB"`
	L4ByteTx uint64 `json:"l4_byte_tx" category:"$metrics" sub:"NPB"`
	L4ByteRx uint64 `json:"l4_byte_rx" category:"$metrics" sub:"NPB"`
}

func (m *UsageMeter) Reverse() {
	m.PacketTx, m.PacketRx = m.PacketRx, m.PacketTx
	m.ByteTx, m.ByteRx = m.ByteRx, m.ByteTx
	m.L3ByteTx, m.L3ByteRx = m.L3ByteRx, m.L3ByteTx
	m.L4ByteTx, m.L4ByteRx = m.L4ByteRx, m.L4ByteTx
}

func (m *UsageMeter) ID() uint8 {
	return ACL_ID
}

func (m *UsageMeter) Name() string {
	return MeterVTAPNames[m.ID()]
}

func (m *UsageMeter) VTAPName() string {
	return MeterVTAPNames[m.ID()]
}

func (m *UsageMeter) WriteToPB(p *pb.UsageMeter) {
	p.PacketTx = m.PacketTx
	p.PacketRx = m.PacketRx
	p.ByteTx = m.ByteTx
	p.ByteRx = m.ByteRx
	p.L3ByteTx = m.L3ByteTx
	p.L3ByteRx = m.L3ByteRx
	p.L4ByteTx = m.L4ByteTx
	p.L4ByteRx = m.L4ByteRx
}

func (m *UsageMeter) ReadFromPB(p *pb.UsageMeter) {
	m.PacketTx = p.PacketTx
	m.PacketRx = p.PacketRx
	m.ByteTx = p.ByteTx
	m.ByteRx = p.ByteRx
	m.L3ByteTx = p.L3ByteTx
	m.L3ByteRx = p.L3ByteRx
	m.L4ByteTx = p.L4ByteTx
	m.L4ByteRx = p.L4ByteRx
}

func (m *UsageMeter) SortKey() uint64 {
	return uint64(m.ByteTx) + uint64(m.ByteRx)
}

func (m *UsageMeter) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *UsageMeter) MarshalTo(b []byte) int {
	offset := 0
	offset += copy(b[offset:], "packet_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.PacketTx, 10))
	offset += copy(b[offset:], "i,packet_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.PacketRx, 10))
	offset += copy(b[offset:], "i,packet=")
	offset += copy(b[offset:], strconv.FormatUint(m.PacketTx+m.PacketRx, 10))
	offset += copy(b[offset:], "i,byte_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.ByteTx, 10))
	offset += copy(b[offset:], "i,byte_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.ByteRx, 10))
	offset += copy(b[offset:], "i,byte=")
	offset += copy(b[offset:], strconv.FormatUint(m.ByteTx+m.ByteRx, 10))
	offset += copy(b[offset:], "i,l3_byte_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.L3ByteTx, 10))
	offset += copy(b[offset:], "i,l3_byte_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.L3ByteRx, 10))
	offset += copy(b[offset:], "i,l4_byte_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.L4ByteTx, 10))
	offset += copy(b[offset:], "i,l4_byte_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.L4ByteRx, 10))
	b[offset] = 'i'
	offset++

	return offset
}

const (
	USAGE_PACKET_TX = iota
	USAGE_PACKET_RX
	USAGE_PACKET

	USAGE_BYTE_TX
	USAGE_BYTE_RX
	USAGE_BYTE

	USAGE_L3_BYTE_TX
	USAGE_L3_BYTE_RX
	USAGE_L4_BYTE_TX
	USAGE_L4_BYTE_RX
)

// Columns列和WriteBlock的列需要一一对应
func UsageMeterColumns() []*ckdb.Column {
	return ckdb.NewColumnsWithComment(
		[][2]string{
			USAGE_PACKET_TX: {"packet_tx", "累计发送总包数"},
			USAGE_PACKET_RX: {"packet_rx", "累计接收总包数"},
			USAGE_PACKET:    {"packet", "累计总包数"},

			USAGE_BYTE_TX: {"byte_tx", "累计发送总字节数"},
			USAGE_BYTE_RX: {"byte_rx", "累计接收总字节数"},
			USAGE_BYTE:    {"byte", "累计总字节数"},

			USAGE_L3_BYTE_TX: {"l3_byte_tx", "累计发送网络层负载总字节数"},
			USAGE_L3_BYTE_RX: {"l3_byte_rx", "累计接收网络层负载总字节数"},
			USAGE_L4_BYTE_TX: {"l4_byte_tx", "累计发送应用层负载总字节数"},
			USAGE_L4_BYTE_RX: {"l4_byte_rx", "累计接收应用层负载总字节数"},
		},
		ckdb.UInt64)
}

// WriteBlock需要和Colums的列一一对应
func (m *UsageMeter) WriteBlock(block *ckdb.Block) {
	block.Write(
		m.PacketTx,
		m.PacketRx,
		m.PacketTx+m.PacketRx,

		m.ByteTx,
		m.ByteRx,
		m.ByteTx+m.ByteRx,

		m.L3ByteTx,
		m.L3ByteRx,
		m.L4ByteTx,
		m.L4ByteRx,
	)
}

func (m *UsageMeter) Merge(other *UsageMeter) {
	m.PacketTx += other.PacketTx
	m.PacketRx += other.PacketRx
	m.ByteTx += other.ByteTx
	m.ByteRx += other.ByteRx
	m.L3ByteTx += other.L3ByteTx
	m.L3ByteRx += other.L3ByteRx
	m.L4ByteTx += other.L4ByteTx
	m.L4ByteRx += other.L4ByteRx
}

func (m *UsageMeter) ConcurrentMerge(other Meter) {
	if other, ok := other.(*UsageMeter); ok {
		m.Merge(other)
	}
}

func (m *UsageMeter) SequentialMerge(other Meter) {
	m.ConcurrentMerge(other)
}
