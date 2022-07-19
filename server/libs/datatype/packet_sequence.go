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
	"encoding/binary"
	"errors"
	"time"

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
	PRECISION_SECOND = uint8(iota)
	PRECISION_100_MILL_SECOND
	PRECISION_10_MILL_SECOND
	PRECISION_MILL_SECOND
	PRECISION_100_MICRO_SECOND
	PRECISION_10_MICRO_SECOND
	PRECISION_MICRO_SECOND
	PRECISION_100_NANO_SECOND // 7B can only save timestamps with an accuracy of 100 nanoseconds
	PRECISION_10_NANO_SECOND
	PRECISION_NANO_SECOND
)

// ConvertDuration2Timestamp accounting the precision to convert the duration to the timestamp
func ConvertDuration2Timestamp(precision uint8, duration time.Duration) uint64 {
	var timestamp = uint64(0)
	switch precision {
	case PRECISION_SECOND:
		timestamp = uint64(duration.Seconds())
	case PRECISION_100_MILL_SECOND:
		timestamp = uint64(duration.Round(100*time.Millisecond).Milliseconds() / 100)
	case PRECISION_10_MILL_SECOND:
		timestamp = uint64(duration.Round(10*time.Millisecond).Milliseconds() / 10)
	case PRECISION_MILL_SECOND:
		timestamp = uint64(duration.Milliseconds())
	case PRECISION_100_MICRO_SECOND:
		timestamp = uint64(duration.Round(100*time.Microsecond).Microseconds() / 100)
	case PRECISION_10_MICRO_SECOND:
		timestamp = uint64(duration.Round(10*time.Microsecond).Microseconds() / 10)
	case PRECISION_MICRO_SECOND:
		timestamp = uint64(duration.Microseconds())
	case PRECISION_100_NANO_SECOND:
		timestamp = uint64(duration.Round(100*time.Nanosecond).Nanoseconds() / 100)
	default:
		timestamp = uint64(duration.Milliseconds())
	}
	return timestamp
}

type UncompressedPacketSequenceBlock struct {
	FlowId          uint64
	FullPacketsData []FullPacketData
	TimePrecision   uint8
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
	OptSack          []byte
}

func DecodePacketSequenceBlock(decoder *codec.SimpleDecoder) ([]*UncompressedPacketSequenceBlock, error) {
	var uncompressedPacketSequenceBlocks []*UncompressedPacketSequenceBlock
	for !decoder.IsEnd() {
		l := decoder.ReadU32()
		u := &UncompressedPacketSequenceBlock{}
		flowId := decoder.ReadU64()
		u.FlowId = flowId
		l -= 8
		lastPacketsData := [2]FullPacketData{}
		var (
			hasLastPacket [2]bool // 0: hasLastC2SPacket, 1: hasLastS2CPacket
			lastTimestamp uint64
			offset        int
		)
		for l > 0 {
			offset = decoder.Offset()
			var d FullPacketData
			if lastTimestamp == 0 { // it means that this packet is the first packet
				timestamp := decoder.ReadU64()
				u.TimePrecision = uint8(timestamp >> 56)
				lastTimestamp = timestamp & uint64((1<<56)-1)
			} else {
				delta := decoder.ReadVarintU64()
				lastTimestamp += delta
			}
			d.Timestamp = lastTimestamp

			fieldFlag := decoder.ReadU16()
			d.Direction = PacketDirection(fieldFlag >> 15)

			lowFieldFlag := uint8(fieldFlag)
			if lowFieldFlag&HAS_FLAG > 0 {
				d.Flags = decoder.ReadU8()
			} else {
				d.Flags = lastPacketsData[d.Direction].Flags
			}
			if lowFieldFlag&HAS_SEQ > 0 {
				if hasLastPacket[d.Direction] {
					delta := decoder.ReadZigzagU32()
					d.Seq = lastPacketsData[d.Direction].Seq + delta
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
					sack := make([]byte, 4)
					binary.BigEndian.PutUint32(sack, lastSack)
					d.OptSack = append(d.OptSack, sack...)
					lastSack += decoder.ReadVarintU32()
					binary.BigEndian.PutUint32(sack, lastSack)
					d.OptSack = append(d.OptSack, sack...)
					for i := uint8(0); i < sackNum-1; i++ {
						lastSack += decoder.ReadVarintU32()
						binary.BigEndian.PutUint32(sack, lastSack)
						d.OptSack = append(d.OptSack, sack...)
						lastSack += decoder.ReadVarintU32()
						binary.BigEndian.PutUint32(sack, lastSack)
						d.OptSack = append(d.OptSack, sack...)
					}
				}
			}
			hasLastPacket[d.Direction] = true
			lastPacketsData[d.Direction] = d
			u.FullPacketsData = append(u.FullPacketsData, d)
			l -= uint32(decoder.Offset() - offset)
			if decoder.Failed() {
				return nil, errors.New("decode packet sequence block failed")
			}
		}
		uncompressedPacketSequenceBlocks = append(uncompressedPacketSequenceBlocks, u)
	}
	return uncompressedPacketSequenceBlocks, nil
}
