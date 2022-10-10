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

package jsonify

import (
	"fmt"
	"time"

	"github.com/deepflowys/deepflow/server/libs/ckdb"
	"github.com/deepflowys/deepflow/server/libs/codec"
	"github.com/deepflowys/deepflow/server/libs/pool"
)

type L4Packet struct {
	EndTime     uint64
	FlowID      uint64
	VtapID      uint16
	PacketCount uint32
	PacketBatch []byte
}

func L4PacketColumns() []*ckdb.Column {
	return []*ckdb.Column{
		ckdb.NewColumn("time", ckdb.DateTime).SetComment("精度: 秒"),
		ckdb.NewColumn("end_time", ckdb.DateTime64us).SetComment("精度: 微秒"),
		ckdb.NewColumn("flow_id", ckdb.UInt64).SetIndex(ckdb.IndexMinmax),
		ckdb.NewColumn("vtap_id", ckdb.UInt16).SetIndex(ckdb.IndexSet),
		ckdb.NewColumn("packet_count", ckdb.UInt32).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("packet_batch", ckdb.ArrayUInt8).SetIndex(ckdb.IndexNone),
	}
}

func (s *L4Packet) WriteBlock(block *ckdb.Block) error {
	if err := block.WriteDateTime(uint32(s.EndTime / uint64(time.Microsecond))); err != nil {
		return err
	}
	if err := block.WriteUInt64(s.EndTime); err != nil {
		return err
	}
	if err := block.WriteUInt64(s.FlowID); err != nil {
		return err
	}
	if err := block.WriteUInt16(s.VtapID); err != nil {
		return err
	}
	if err := block.WriteUInt32(s.PacketCount); err != nil {
		return err
	}
	if err := block.WriteArrayByte(s.PacketBatch); err != nil {
		return err
	}

	return nil
}

func (p *L4Packet) Release() {
	ReleaseL4Packet(p)
}

func (p *L4Packet) String() string {
	return fmt.Sprintf("L4Packet: %+v\n", *p)
}

var poolL4Packet = pool.NewLockFreePool(func() interface{} {
	return new(L4Packet)
})

func AcquireL4Packet() *L4Packet {
	l := poolL4Packet.Get().(*L4Packet)
	return l
}

func ReleaseL4Packet(l *L4Packet) {
	if l == nil {
		return
	}
	t := l.PacketBatch[:0]
	*l = L4Packet{}
	l.PacketBatch = t
	poolL4Packet.Put(l)
}

func DecodePacketSequence(decoder *codec.SimpleDecoder, vtapID uint16) *L4Packet {
	l4Packet := AcquireL4Packet()
	l4Packet.VtapID = vtapID
	blockSize := decoder.ReadU32()
	l4Packet.FlowID = decoder.ReadU64()
	endTimePacketCount := decoder.ReadU64()
	l4Packet.EndTime = endTimePacketCount << 8
	l4Packet.PacketCount = uint32(endTimePacketCount >> 56)
	l4Packet.PacketBatch = append(l4Packet.PacketBatch, decoder.ReadBytesN(int(blockSize)-16)...)

	return l4Packet
}
