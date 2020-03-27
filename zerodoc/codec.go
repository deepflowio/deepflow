package zerodoc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

const (
	CODEC_VERSION_OFFSET   = 0
	CODEC_SEQUENCE_OFFSET  = CODEC_VERSION_OFFSET + 32/8
	CODEC_TIMESTAMP_OFFSET = CODEC_SEQUENCE_OFFSET + 64/8
)

// send to zero
// Protocol:
//     version     uint32
//     sequence    uint64
//     timestamp   uint32
//     tag         Tag (bytes)
//     meterType   uint8
//     meter       Meter (bytes)
//     actionFlags uint32
func Encode(sequence uint64, doc *app.Document, encoder *codec.SimpleEncoder) error {
	if doc.Tag == nil || doc.Meter == nil {
		return errors.New("No tag or meter in document")
	}

	var msgType MessageType
	switch v := doc.Meter.(type) {
	case *GeoMeter:
		msgType = MSG_GEO
	case *FlowSecondMeter:
		msgType = MSG_FLOW_SECOND
	case *FlowMeter:
		msgType = MSG_FLOW
	case *VTAPUsageMeter:
		msgType = MSG_PACKET
	default:
		return fmt.Errorf("Unknown supported type %T", v)
	}

	encoder.WriteU32(app.VERSION)
	encoder.WriteU64(sequence)
	encoder.WriteU32(doc.Timestamp)

	var tag *Tag
	tag, ok := doc.Tag.(*Tag)
	if !ok {
		return fmt.Errorf("Unknown supported tag type %T", doc.Tag)
	}
	tag.Encode(encoder)
	encoder.WriteU8(uint8(msgType))
	doc.Meter.Encode(encoder)
	encoder.WriteU32(uint32(doc.Flags))

	return nil
}

// 由于trident等将多个doc合并为1个块进行发送， 只设置第一个doc的sequence即可
func SetSequence(sequence uint64, chunk []byte) {
	// 先偏移4个字节的VERSION字段
	binary.LittleEndian.PutUint64(chunk[CODEC_SEQUENCE_OFFSET:], sequence)
}

func GetSequence(chunk []byte) uint64 {
	// 先偏移4个字节的VERSION字段
	return binary.LittleEndian.Uint64(chunk[CODEC_SEQUENCE_OFFSET:])
}

func GetTimestamp(chunk []byte) uint32 {
	return binary.LittleEndian.Uint32(chunk[CODEC_TIMESTAMP_OFFSET:])
}

// The return Document, must call app.ReleaseDocument to release after used
func Decode(decoder *codec.SimpleDecoder) (*app.Document, error) {
	if decoder == nil {
		return nil, errors.New("No input decoder")
	}

	if version := decoder.ReadU32(); version != app.VERSION {
		return nil, errors.New(fmt.Sprintf("message version incorrect, expect %d, found %d.", app.VERSION, version))
	}
	decoder.ReadU64() // sequence

	doc := app.AcquireDocument()

	doc.Timestamp = decoder.ReadU32()

	tag := AcquireTag()
	tag.Field = AcquireField()
	tag.Decode(decoder)
	doc.Tag = tag

	msgType := decoder.ReadU8()
	switch MessageType(msgType) {
	case MSG_GEO:
		doc.Meter = AcquireGeoMeter()
	case MSG_FLOW_SECOND:
		doc.Meter = AcquireFlowSecondMeter()
	case MSG_FLOW:
		doc.Meter = AcquireFlowMeter()
	case MSG_PACKET:
		doc.Meter = AcquireVTAPUsageMeter()
	default:
		app.ReleaseDocument(doc)
		return nil, errors.New(fmt.Sprintf("Error meter type %v", msgType))
	}
	doc.Meter.Decode(decoder)
	doc.Flags = app.DocumentFlag(decoder.ReadU32())

	if decoder.Failed() {
		app.ReleaseDocument(doc)
		return nil, errors.New("Decode failed")
	}

	return doc, nil
}

func GetMsgType(db, rp string) (MessageType, error) {
	var msgType MessageType

	if db == "vtap_360_acl" {
		return MSG_PACKET, nil
	}
	if strings.HasPrefix(db, MeterVTAPNames[PACKET_ID]) {
		msgType = MSG_PACKET
	} else if strings.HasPrefix(db, MeterVTAPNames[GEO_ID]) {
		msgType = MSG_GEO
	} else if strings.HasPrefix(db, MeterVTAPNames[FLOW_ID]) {
		if rp == "s1" {
			msgType = MSG_FLOW_SECOND
		} else if rp == "autogen" {
			msgType = MSG_FLOW
		} else {
			return MSG_INVILID, fmt.Errorf("Unsupport rp %s", rp)
		}
	} else {
		return MSG_INVILID, fmt.Errorf("unsupport db %s", db)
	}

	return msgType, nil
}

// send to reciter
// Protocol:
//     version     uint32
//     sequence    uint64
//     timestamp   uint32
//     tag         Tag (bytes)
//     meterType   uint8
//     meter       Meter (bytes)
//     actionFlags uint32
func EncodeRow(tag *Tag, msgType MessageType, columnIDs []uint8, timestamp int64, columnValues []interface{}, encoder *codec.SimpleEncoder) error {
	encoder.WriteU32(app.VERSION) // version
	encoder.WriteU64(0)           // sequence

	encoder.WriteU32(uint32(timestamp / int64(time.Second))) // timestamp

	if err := tag.FillValues(columnIDs, columnValues); err != nil {
		return err
	}
	tag.Encode(encoder)

	encoder.WriteU8(uint8(msgType))

	switch msgType {
	case MSG_GEO:
		var m GeoMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case MSG_FLOW_SECOND:
		var m FlowSecondMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case MSG_FLOW:
		var m FlowMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case MSG_PACKET:
		var m VTAPUsageMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	default:
		return fmt.Errorf("Unknown supported msgType %d", msgType)
	}

	encoder.WriteU32(0) // actionflag

	return nil
}
