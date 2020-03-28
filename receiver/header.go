package receiver

import (
	"encoding/binary"
	"fmt"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
)

const (
	HEADER_LEN             = 14
	HEADER_VERSION_OFFSET  = 0
	HEADER_SEQUENCE_OFFSET = HEADER_VERSION_OFFSET + 4
	HEADER_LENGTH_OFFSET   = HEADER_SEQUENCE_OFFSET + 8
)

type DataType byte

const (
	ZeroDoc DataType = iota
	TaggedFlow
)

// 多个document和taggeflow encode时共用一个header
type Header struct {
	Version  uint32 // 用来校验encode和decode是否配套
	Sequence uint64 // udp发送时，用来校验是否丢包
	Length   uint16 // tcp发送时，需要按此长度收齐数据后，再decode
}

func (h *Header) Encode(chunk []byte) {
	binary.LittleEndian.PutUint32(chunk[HEADER_VERSION_OFFSET:], h.Version)
	binary.LittleEndian.PutUint64(chunk[HEADER_SEQUENCE_OFFSET:], h.Sequence)
	binary.LittleEndian.PutUint16(chunk[HEADER_LENGTH_OFFSET:], h.Length)
}

func (h *Header) Decode(buf []byte) {
	h.Version = binary.LittleEndian.Uint32(buf[HEADER_VERSION_OFFSET:])
	h.Sequence = binary.LittleEndian.Uint64(buf[HEADER_SEQUENCE_OFFSET:])
	h.Length = binary.LittleEndian.Uint16(buf[HEADER_LENGTH_OFFSET:])
}

func (h *Header) CheckVersion(dataType DataType) error {
	var expectVersion uint32
	if dataType == ZeroDoc {
		expectVersion = app.VERSION
	} else {
		expectVersion = datatype.VERSION
	}
	if h.Version != expectVersion {
		return fmt.Errorf("message version incorrect, expect %d, found %d.", expectVersion, h.Version)
	}
	return nil
}
