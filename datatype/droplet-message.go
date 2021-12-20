package datatype

import (
	"encoding/binary"
	"fmt"
)

// 本消息格式仅用于同droplet通信:
//     1. FrameSize用于粘包，为了简化包头压缩算法逻辑，UDP发送时也需要预留FrameSize但是内容可以为0
//     2. MessageType标注消息类型
//     3. MessageValue为具体的消息内容
// --------------------------------------------------------
// | FrameSize(4B) | MessageType(1B) |  MessageValue(...) |
// --------------------------------------------------------
const (
	MESSAGE_TYPE_COMPRESS = iota
	MESSAGE_TYPE_SYSLOG
	MESSAGE_TYPE_STATSD

	MESSAGE_TYPE_METRICS
	MESSAGE_TYPE_TAGGEDFLOW
	MESSAGE_TYPE_PROTOCOLLOG

	MESSAGE_TYPE_DFSTATSD
	MESSAGE_TYPE_MAX
)

var MessageTypeString = [MESSAGE_TYPE_MAX]string{
	"pcap",
	"syslog",
	"statsd",
	"metrics",
	"l4_log",
	"l7_log",
	"df_statsd",
}

const (
	DROPLET_PORT = 20033

	// pcap压缩包头发送时最大长度为：MESSAGE_HEADER_LEN + compressor header + 14 + 4 * n + 65535, 这里取整使用66000
	MESSAGE_FRAME_SIZE_MAX = 66000
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
	FrameSize uint32 // tcp发送时，需要按此长度收齐数据后，再decode (FrameSize总长度，包含了 BaseHeader的长度)
	Type      uint8  // 消息类型
}

func (h *BaseHeader) Encode(chunk []byte) {
	binary.BigEndian.PutUint32(chunk[MESSAGE_FRAME_SIZE_OFFSET:], h.FrameSize)
	chunk[MESSAGE_TYPE_OFFSET] = uint8(h.Type)
}

func (h *BaseHeader) Decode(buf []byte) error {
	h.FrameSize = binary.BigEndian.Uint32(buf[MESSAGE_FRAME_SIZE_OFFSET:])
	h.Type = uint8(buf[MESSAGE_TYPE_OFFSET])

	switch h.Type {
	case MESSAGE_TYPE_COMPRESS:
		if h.FrameSize <= MESSAGE_HEADER_LEN {
			return fmt.Errorf("header type is %d frame size is %d smaller than header length %d,  invalid", h.Type, h.FrameSize, MESSAGE_HEADER_LEN)
		}
	case MESSAGE_TYPE_SYSLOG, MESSAGE_TYPE_STATSD, MESSAGE_TYPE_DFSTATSD:
		return nil
	case MESSAGE_TYPE_METRICS, MESSAGE_TYPE_TAGGEDFLOW, MESSAGE_TYPE_PROTOCOLLOG:
		if h.FrameSize <= MESSAGE_HEADER_LEN+FLOW_HEADER_LEN {
			return fmt.Errorf("header type is %d frame size is %d smaller than header length %d,  invalid", h.Type, h.FrameSize, MESSAGE_HEADER_LEN+FLOW_HEADER_LEN)
		}
	default:
		return fmt.Errorf("header type %d is exceed MESSAGE_TYPE_MAX, invalid", h.Type)
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
