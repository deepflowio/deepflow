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

package datatype

import (
	"errors"

	"github.com/deepflowys/deepflow/server/libs/codec"
)

const (
	HAS_OPT_SACK     = 1 << iota // 0000 0001
	HAS_OPT_WS                   // 0000 0010
	HAS_OPT_MSS                  // 0000 0100
	HAS_WINDOW_SIZE              // 0000 1000
	HAS_PAYLOAD_SIZE             // 0001 0000
	HAS_ACK                      // 0010 0000
	HAS_SEQ                      // 0100 0000
	HAS_FLAG                     // 1000 0000
)

const (
	DIRECTION_OFFSET     = 15
	FIRST_TIMESTAMP_MASK = uint64((1 << 56) - 1)
)

type UncompressedPacketSequenceBlock struct {
	FlowId          uint64
	StartTime       uint32
	EndTimeDelta    uint16
	PacketCount     uint16
	TimePrecision   uint8
	FullPacketsData []FullPacketData
}

type FullPacketData struct {
	Timestamp        uint64
	Seq              uint32
	Ack              uint32
	PayloadLen       uint16
	WinSize          uint16
	OptMss           uint16
	OptWs            uint8
	Flags            uint8
	Direction        PacketDirection
	OptSackPermitted bool
	OptSack          []uint32
}

func DecodePacketSequenceBlock(decoder *codec.SimpleDecoder, blocks []*UncompressedPacketSequenceBlock) ([]*UncompressedPacketSequenceBlock, int, error) {
	blocksCount := 0
	blockIndex := 0
	oldBlockSize := len(blocks)
	for !decoder.IsEnd() { // if decoder is not end, it still has blocks
		length := decoder.ReadU32() // the block's length
		var block *UncompressedPacketSequenceBlock
		if blockIndex < oldBlockSize && blocks[blockIndex] != nil {
			block = blocks[blockIndex] // reuse []*UncompressedPacketSequenceBlock
		} else if blockIndex < oldBlockSize {
			block = &UncompressedPacketSequenceBlock{}
			blocks[blockIndex] = block
		} else {
			block = &UncompressedPacketSequenceBlock{}
		}
		block.FlowId = decoder.ReadU64()
		block.StartTime = decoder.ReadU32()
		block.EndTimeDelta = decoder.ReadU16()
		block.PacketCount = decoder.ReadU16()
		length -= 16 // 16 = flowId(8B) + startTime(4B) + endTimeDelta(2B) + packetCount(2B)
		lastPacketsData := [2]FullPacketData{}
		var (
			hasLastPacket [2]bool // 0: hasLastC2SPacket, 1: hasLastS2CPacket
			lastTimestamp uint64
			offset        int
		)
		oldFullPacketsDataSize := len(block.FullPacketsData)
		fullPacketsDataIndex := 0
		for length > 0 { //
			offset = decoder.Offset()
			var d FullPacketData
			if fullPacketsDataIndex < oldFullPacketsDataSize {
				d = block.FullPacketsData[fullPacketsDataIndex] // reuse block.FullPacketsData
			}
			if lastTimestamp == 0 { // it means that this packet is the first packet
				timestamp := decoder.ReadU64()
				block.TimePrecision = uint8(timestamp >> 56)     // get higher 1 byte, 0: second ~ 9: nanosecond
				lastTimestamp = timestamp & FIRST_TIMESTAMP_MASK // get lower 7 bytes
			} else {
				delta := decoder.ReadVarintU64()
				lastTimestamp += delta
			}
			d.Timestamp = lastTimestamp

			fieldFlag := decoder.ReadU16()
			d.Direction = PacketDirection(fieldFlag >> DIRECTION_OFFSET)

			lowFieldFlag := uint8(fieldFlag)
			if lowFieldFlag&HAS_FLAG > 0 {
				d.Flags = decoder.ReadU8()
			} else {
				d.Flags = lastPacketsData[d.Direction].Flags
			}
			if lowFieldFlag&HAS_SEQ > 0 {
				if hasLastPacket[d.Direction] {
					d.Seq = lastPacketsData[d.Direction].Seq + decoder.ReadZigzagU32()
				} else {
					d.Seq = decoder.ReadU32()
				}
			} else {
				d.Seq = lastPacketsData[d.Direction].Seq
			}
			if lowFieldFlag&HAS_ACK > 0 {
				if hasLastPacket[d.Direction] {
					d.Ack = lastPacketsData[d.Direction].Ack + decoder.ReadZigzagU32()
				} else {
					d.Ack = decoder.ReadU32()
				}
			} else {
				d.Ack = lastPacketsData[d.Direction].Ack
			}
			if lowFieldFlag&HAS_PAYLOAD_SIZE > 0 {
				d.PayloadLen = decoder.ReadU16()
			} else {
				d.PayloadLen = lastPacketsData[d.Direction].PayloadLen
			}
			if lowFieldFlag&HAS_WINDOW_SIZE > 0 {
				d.WinSize = decoder.ReadU16()
			} else {
				d.WinSize = lastPacketsData[d.Direction].WinSize
			}
			if lowFieldFlag&HAS_OPT_MSS > 0 {
				d.OptMss = decoder.ReadU16()
			}
			if lowFieldFlag&HAS_OPT_WS > 0 {
				d.OptWs = decoder.ReadU8()
			}
			if lowFieldFlag&HAS_OPT_SACK > 0 {
				sackFlag := decoder.ReadU8()
				if sackFlag>>3 > 0 {
					d.OptSackPermitted = true
				}
				sackNum := sackFlag & 0x7
				if sackNum > 0 {
					lastSack := decoder.ReadU32()
					d.OptSack = append(d.OptSack, lastSack)
					for i := uint8(0); i < sackNum*2-1; i++ {
						lastSack += decoder.ReadVarintU32()
						d.OptSack = append(d.OptSack, lastSack)
					}
				}
			}
			hasLastPacket[d.Direction] = true
			lastPacketsData[d.Direction] = d
			if fullPacketsDataIndex >= oldFullPacketsDataSize {
				block.FullPacketsData = append(block.FullPacketsData, d)
			}
			fullPacketsDataIndex++

			length -= uint32(decoder.Offset() - offset)
			if decoder.Failed() {
				return nil, 0, errors.New("decode packet sequence block failed")
			}
		}
		if blockIndex >= oldBlockSize {
			blocks = append(blocks, block)
		}
		blockIndex++
		blocksCount++
	}
	return blocks, blocksCount, nil
}
