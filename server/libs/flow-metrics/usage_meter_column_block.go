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
	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type UsageMeterBlock struct {
	ColPacketTx proto.ColUInt64
	ColPacketRx proto.ColUInt64
	ColPacket   proto.ColUInt64
	ColByteTx   proto.ColUInt64
	ColByteRx   proto.ColUInt64
	ColByte     proto.ColUInt64
	ColL3ByteTx proto.ColUInt64
	ColL3ByteRx proto.ColUInt64
	ColL4ByteTx proto.ColUInt64
	ColL4ByteRx proto.ColUInt64
}

func (b *UsageMeterBlock) Reset() {
	b.ColPacketTx.Reset()
	b.ColPacketRx.Reset()
	b.ColPacket.Reset()
	b.ColByteTx.Reset()
	b.ColByteRx.Reset()
	b.ColByte.Reset()
	b.ColL3ByteTx.Reset()
	b.ColL3ByteRx.Reset()
	b.ColL4ByteTx.Reset()
	b.ColL4ByteRx.Reset()
}

func (b *UsageMeterBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_PACKET_TX, Data: &b.ColPacketTx},
		proto.InputColumn{Name: ckdb.COLUMN_PACKET_RX, Data: &b.ColPacketRx},
		proto.InputColumn{Name: ckdb.COLUMN_PACKET, Data: &b.ColPacket},
		proto.InputColumn{Name: ckdb.COLUMN_BYTE_TX, Data: &b.ColByteTx},
		proto.InputColumn{Name: ckdb.COLUMN_BYTE_RX, Data: &b.ColByteRx},
		proto.InputColumn{Name: ckdb.COLUMN_BYTE, Data: &b.ColByte},
		proto.InputColumn{Name: ckdb.COLUMN_L3_BYTE_TX, Data: &b.ColL3ByteTx},
		proto.InputColumn{Name: ckdb.COLUMN_L3_BYTE_RX, Data: &b.ColL3ByteRx},
		proto.InputColumn{Name: ckdb.COLUMN_L4_BYTE_TX, Data: &b.ColL4ByteTx},
		proto.InputColumn{Name: ckdb.COLUMN_L4_BYTE_RX, Data: &b.ColL4ByteRx},
	)
}

func (n *UsageMeter) NewColumnBlock() ckdb.CKColumnBlock {
	return &UsageMeterBlock{}
}

func (n *UsageMeter) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*UsageMeterBlock)
	block.ColPacketTx.Append(n.PacketTx)
	block.ColPacketRx.Append(n.PacketRx)
	block.ColPacket.Append(n.PacketTx + n.PacketRx)
	block.ColByteTx.Append(n.ByteTx)
	block.ColByteRx.Append(n.ByteRx)
	block.ColByte.Append(n.ByteTx + n.ByteRx)
	block.ColL3ByteTx.Append(n.L3ByteTx)
	block.ColL3ByteRx.Append(n.L3ByteRx)
	block.ColL4ByteTx.Append(n.L4ByteTx)
	block.ColL4ByteRx.Append(n.L4ByteRx)
}
