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

type FullPacketData struct {
	Timestamp        uint64          `json:"timestamp"`
	Seq              uint32          `json:"seq"`
	Ack              uint32          `json:"ack"`
	PayloadLen       uint16          `json:"payload_len"`
	WinSize          uint16          `json:"win_size"`
	OptMss           uint16          `json:"opt_mss"`
	OptWs            uint8           `json:"opt_ws"`
	Flags            uint8           `json:"flags"`
	Direction        PacketDirection `json:"direction"`
	OptSackPermitted bool            `json:"opt_sack_permitted"`
	OptSack          []uint32        `json:"opt_sack"`
}

var emptyFullPacketData = FullPacketData{}

func DecodePacketSequenceBlock(decoder *codec.SimpleDecoder, packets []*FullPacketData) ([]*FullPacketData, int, error) {
	var (
		packetIndex   int
		hasLastPacket [2]bool // 0: hasLastC2SPacket, 1: hasLastS2CPacket
		lastTimestamp uint64
	)
	oldPacketNum := len(packets)
	lastPacketsData := [2]*FullPacketData{&emptyFullPacketData, &emptyFullPacketData}

	for !decoder.IsEnd() {
		var packet *FullPacketData
		if packetIndex < oldPacketNum && packets[packetIndex] != nil {
			packet = packets[packetIndex] // reuse []*FullPacketData
		} else if packetIndex < oldPacketNum {
			packet = &FullPacketData{}
			packets[packetIndex] = packet
		} else {
			packet = &FullPacketData{}
			packets = append(packets, packet)
		}

		if lastTimestamp == 0 { // it means that this packet is the first packet
			timestamp := decoder.ReadU64()
			// TODO: the higher 1 byte is time precision, reserved, 0: nanosecond ~ 9: second
			lastTimestamp = timestamp & FIRST_TIMESTAMP_MASK // get lower 7 bytes, timestamp unit: microseconds
		} else {
			delta := decoder.ReadVarintU64()
			lastTimestamp += delta
		}
		packet.Timestamp = lastTimestamp

		fieldFlag := decoder.ReadU16()
		packet.Direction = PacketDirection(fieldFlag >> DIRECTION_OFFSET)

		lowFieldFlag := uint8(fieldFlag)
		if lowFieldFlag&HAS_FLAG > 0 {
			packet.Flags = decoder.ReadU8()
		} else {
			packet.Flags = lastPacketsData[packet.Direction].Flags
		}
		if lowFieldFlag&HAS_SEQ > 0 {
			if hasLastPacket[packet.Direction] {
				packet.Seq = lastPacketsData[packet.Direction].Seq + decoder.ReadZigzagU32()
			} else {
				packet.Seq = decoder.ReadU32()
			}
		} else {
			packet.Seq = lastPacketsData[packet.Direction].Seq
		}
		if lowFieldFlag&HAS_ACK > 0 {
			if hasLastPacket[packet.Direction] {
				packet.Ack = lastPacketsData[packet.Direction].Ack + decoder.ReadZigzagU32()
			} else {
				packet.Ack = decoder.ReadU32()
			}
		} else {
			packet.Ack = lastPacketsData[packet.Direction].Ack
		}
		if lowFieldFlag&HAS_PAYLOAD_SIZE > 0 {
			packet.PayloadLen = decoder.ReadU16()
		} else {
			packet.PayloadLen = lastPacketsData[packet.Direction].PayloadLen
		}
		if lowFieldFlag&HAS_WINDOW_SIZE > 0 {
			packet.WinSize = decoder.ReadU16()
		} else {
			packet.WinSize = lastPacketsData[packet.Direction].WinSize
		}
		if lowFieldFlag&HAS_OPT_MSS > 0 {
			packet.OptMss = decoder.ReadU16()
		}
		if lowFieldFlag&HAS_OPT_WS > 0 {
			packet.OptWs = decoder.ReadU8()
		}
		if lowFieldFlag&HAS_OPT_SACK > 0 {
			sackFlag := decoder.ReadU8()
			if sackFlag>>3 > 0 {
				packet.OptSackPermitted = true
			}
			sackNum := sackFlag & 0x7
			if sackNum > 0 {
				lastSack := decoder.ReadU32()
				packet.OptSack = append(packet.OptSack, lastSack)
				for i := uint8(0); i < sackNum*2-1; i++ {
					lastSack += decoder.ReadVarintU32()
					packet.OptSack = append(packet.OptSack, lastSack)
				}
			}
		}
		hasLastPacket[packet.Direction] = true
		lastPacketsData[packet.Direction] = packet
		packetIndex++
		if decoder.Failed() {
			return nil, 0, errors.New("decode packet sequence block failed")
		}
	}

	return packets, packetIndex, nil
}
