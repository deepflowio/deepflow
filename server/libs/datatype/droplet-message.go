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

package datatype

import (
	"encoding/binary"
	"fmt"
)

// 本消息格式仅用于同droplet通信:
//  1. FrameSize用于粘包，为了简化包头压缩算法逻辑，UDP发送时也需要预留FrameSize但是内容可以为0
//  2. MessageType标注消息类型
//  3. MessageValue为具体的消息内容
//
// --------------------------------------------------------
// | FrameSize(4B) | MessageType(1B) |  MessageValue(...) |
// --------------------------------------------------------
type MessageType uint8

const (
	MESSAGE_TYPE_COMPRESS MessageType = iota
	MESSAGE_TYPE_SYSLOG
	MESSAGE_TYPE_STATSD

	MESSAGE_TYPE_METRICS
	MESSAGE_TYPE_TAGGEDFLOW
	MESSAGE_TYPE_PROTOCOLLOG
	MESSAGE_TYPE_OPENTELEMETRY
	MESSAGE_TYPE_PROMETHEUS
	MESSAGE_TYPE_TELEGRAF
	MESSAGE_TYPE_PACKETSEQUENCE

	MESSAGE_TYPE_DFSTATS
	MESSAGE_TYPE_OPENTELEMETRY_COMPRESSED
	MESSAGE_TYPE_RAW_PCAP
	MESSAGE_TYPE_PROFILE
	MESSAGE_TYPE_PROC_EVENT
	MESSAGE_TYPE_ALARM_EVENT
	MESSAGE_TYPE_MAX
)

var MessageTypeString = [MESSAGE_TYPE_MAX]string{
	MESSAGE_TYPE_COMPRESS: "compressed_pcap",
	MESSAGE_TYPE_SYSLOG:   "syslog",
	MESSAGE_TYPE_STATSD:   "statsd",

	MESSAGE_TYPE_METRICS:        "metrics",
	MESSAGE_TYPE_TAGGEDFLOW:     "l4_log",
	MESSAGE_TYPE_PROTOCOLLOG:    "l7_log",
	MESSAGE_TYPE_OPENTELEMETRY:  "open_telemetry",
	MESSAGE_TYPE_PROMETHEUS:     "prometheus",
	MESSAGE_TYPE_TELEGRAF:       "telegraf",
	MESSAGE_TYPE_PACKETSEQUENCE: "l4_packet",

	MESSAGE_TYPE_DFSTATS:                  "deepflow_stats",
	MESSAGE_TYPE_OPENTELEMETRY_COMPRESSED: "open_telemetry_compressed",
	MESSAGE_TYPE_RAW_PCAP:                 "raw_pcap",
	MESSAGE_TYPE_PROFILE:                  "profile",
	MESSAGE_TYPE_PROC_EVENT:               "proc_event",
	MESSAGE_TYPE_ALARM_EVENT:              "alarm_event",
}

func (m MessageType) String() string {
	if m < MESSAGE_TYPE_MAX {
		return MessageTypeString[m]
	}
	return "unknown message"
}

type MessageHeaderType uint8

const (
	// 4B + 1B
	HEADER_TYPE_LT MessageHeaderType = iota
	// 4B + 1B, 不校验length
	HEADER_TYPE_LT_NOCHECK
	// 4B + 1B + (4B + 8B +2B)
	HEADER_TYPE_LT_VTAP
	HEADER_TYPE_UNKNOWN
)

var MessageHeaderTypes = [MESSAGE_TYPE_MAX]MessageHeaderType{
	MESSAGE_TYPE_COMPRESS: HEADER_TYPE_LT,
	MESSAGE_TYPE_SYSLOG:   HEADER_TYPE_LT_NOCHECK,
	MESSAGE_TYPE_STATSD:   HEADER_TYPE_LT_NOCHECK,

	MESSAGE_TYPE_METRICS:        HEADER_TYPE_LT_VTAP,
	MESSAGE_TYPE_TAGGEDFLOW:     HEADER_TYPE_LT_VTAP,
	MESSAGE_TYPE_PROTOCOLLOG:    HEADER_TYPE_LT_VTAP,
	MESSAGE_TYPE_OPENTELEMETRY:  HEADER_TYPE_LT_VTAP,
	MESSAGE_TYPE_PROMETHEUS:     HEADER_TYPE_LT_VTAP,
	MESSAGE_TYPE_TELEGRAF:       HEADER_TYPE_LT_VTAP,
	MESSAGE_TYPE_PACKETSEQUENCE: HEADER_TYPE_LT_VTAP,

	MESSAGE_TYPE_DFSTATS:                  HEADER_TYPE_LT_VTAP,
	MESSAGE_TYPE_OPENTELEMETRY_COMPRESSED: HEADER_TYPE_LT_VTAP,
	MESSAGE_TYPE_RAW_PCAP:                 HEADER_TYPE_LT_VTAP,
	MESSAGE_TYPE_PROFILE:                  HEADER_TYPE_LT_VTAP,
	MESSAGE_TYPE_PROC_EVENT:               HEADER_TYPE_LT_VTAP,
	MESSAGE_TYPE_ALARM_EVENT:              HEADER_TYPE_LT_VTAP,
}

func (m MessageType) HeaderType() MessageHeaderType {
	if m < MESSAGE_TYPE_MAX {
		return MessageHeaderTypes[m]
	}
	return HEADER_TYPE_UNKNOWN
}

const (
	// pcap压缩包头发送时最大长度为：MESSAGE_HEADER_LEN + compressor header + 14 + 4 * n + 65535
	// otel的数据长度可达300k
	MESSAGE_FRAME_SIZE_MAX = 512000
)

const (
	MESSAGE_FRAME_SIZE_OFFSET = 0
	MESSAGE_TYPE_OFFSET       = MESSAGE_FRAME_SIZE_OFFSET + 4
	MESSAGE_VALUE_OFFSET      = MESSAGE_TYPE_OFFSET + 1
	MESSAGE_HEADER_LEN        = MESSAGE_VALUE_OFFSET
)

const (
	FLOW_VERSION_OFFSET  = 0
	FLOW_SEQUENCE_OFFSET = FLOW_VERSION_OFFSET + 4
	FLOW_VTAPID_OFFSET   = FLOW_SEQUENCE_OFFSET + 8
	FLOW_HEADER_LEN      = FLOW_VTAPID_OFFSET + 2
)

type BaseHeader struct {
	FrameSize uint32      // tcp发送时，需要按此长度收齐数据后，再decode (FrameSize总长度，包含了 BaseHeader的长度)
	Type      MessageType // 消息类型
}

func (h *BaseHeader) Encode(chunk []byte) {
	binary.BigEndian.PutUint32(chunk[MESSAGE_FRAME_SIZE_OFFSET:], h.FrameSize)
	chunk[MESSAGE_TYPE_OFFSET] = uint8(h.Type)
}

func (h *BaseHeader) Decode(buf []byte) error {
	h.FrameSize = binary.BigEndian.Uint32(buf[MESSAGE_FRAME_SIZE_OFFSET:])
	h.Type = MessageType(buf[MESSAGE_TYPE_OFFSET])

	switch h.Type.HeaderType() {
	case HEADER_TYPE_LT:
		if h.FrameSize <= MESSAGE_HEADER_LEN {
			return fmt.Errorf("header type is %d frame size is %d smaller than header length %d,  invalid", h.Type, h.FrameSize, MESSAGE_HEADER_LEN)
		}
	case HEADER_TYPE_LT_NOCHECK:
		return nil
	case HEADER_TYPE_LT_VTAP:
		if h.FrameSize < MESSAGE_HEADER_LEN+FLOW_HEADER_LEN {
			return fmt.Errorf("header type is %d frame size is %d smaller than header length %d,  invalid", h.Type, h.FrameSize, MESSAGE_HEADER_LEN+FLOW_HEADER_LEN)
		}
	default:
		return fmt.Errorf("header type %d is invalid", h.Type)
	}
	return nil
}

// 多个document和taggeflow encode时共用一个header
type FlowHeader struct {
	Version  uint32 // 用来校验encode和decode是否配套
	Sequence uint64 // udp发送时，用来校验是否丢包
	VTAPID   uint16 // trident的ID
}

func (h *FlowHeader) Encode(chunk []byte) {
	binary.LittleEndian.PutUint32(chunk[FLOW_VERSION_OFFSET:], h.Version)
	binary.LittleEndian.PutUint64(chunk[FLOW_SEQUENCE_OFFSET:], h.Sequence)
	binary.LittleEndian.PutUint16(chunk[FLOW_VTAPID_OFFSET:], h.VTAPID)
}
func (h *FlowHeader) Decode(buf []byte) {
	h.Version = binary.LittleEndian.Uint32(buf[FLOW_VERSION_OFFSET:])
	h.Sequence = binary.LittleEndian.Uint64(buf[FLOW_SEQUENCE_OFFSET:])
	h.VTAPID = binary.LittleEndian.Uint16(buf[FLOW_VTAPID_OFFSET:])
}
