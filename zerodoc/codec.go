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
	case *UsageMeter:
		msgType = MSG_USAGE
	case *PerfMeter:
		msgType = MSG_PERF
	case *GeoMeter:
		msgType = MSG_GEO
	case *FlowMeter:
		msgType = MSG_FLOW
	case *TypeMeter:
		msgType = MSG_TYPE
	case *FPSMeter:
		msgType = MSG_FPS
	case *LogUsageMeter:
		msgType = MSG_LOG_USAGE
	case *VTAPUsageMeter:
		msgType = MSG_VTAP_USAGE
	case *VTAPSimpleMeter:
		msgType = MSG_VTAP_SIMPLE
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
	var meter app.Meter
	switch msgType {
	case MSG_USAGE:
		meter = doc.Meter.(*UsageMeter)
	case MSG_PERF:
		meter = doc.Meter.(*PerfMeter)
	case MSG_GEO:
		meter = doc.Meter.(*GeoMeter)
	case MSG_FLOW:
		meter = doc.Meter.(*FlowMeter)
	case MSG_TYPE:
		meter = doc.Meter.(*TypeMeter)
	case MSG_FPS:
		meter = doc.Meter.(*FPSMeter)
	case MSG_LOG_USAGE:
		meter = doc.Meter.(*LogUsageMeter)
	case MSG_VTAP_USAGE:
		meter = doc.Meter.(*VTAPUsageMeter)
	case MSG_VTAP_SIMPLE:
		meter = doc.Meter.(*VTAPSimpleMeter)
	}
	meter.Encode(encoder)

	encoder.WriteU32(doc.ActionFlags)

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
	case MSG_USAGE:
		m := AcquireUsageMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_PERF:
		m := AcquirePerfMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_GEO:
		m := AcquireGeoMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_FLOW:
		m := AcquireFlowMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_TYPE:
		m := AcquireTypeMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_FPS:
		m := AcquireFPSMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_LOG_USAGE:
		m := AcquireLogUsageMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_VTAP_USAGE:
		m := AcquireVTAPUsageMeter()
		m.Decode(decoder)
		doc.Meter = m
	case MSG_VTAP_SIMPLE:
		m := AcquireVTAPSimpleMeter()
		m.Decode(decoder)
		doc.Meter = m
	default:
		app.ReleaseDocument(doc)
		return nil, errors.New(fmt.Sprintf("Error meter type %v", msgType))
	}

	doc.ActionFlags = decoder.ReadU32()

	if decoder.Failed() {
		app.ReleaseDocument(doc)
		return nil, errors.New("Decode failed")
	}

	return doc, nil
}

func GetMsgType(db string) (MessageType, error) {
	s := strings.Split(db, "_")

	nPrefixSeg := 2
	if strings.HasPrefix(db, "vtap_flow") {
		nPrefixSeg = 3
	}

	if len(s) < nPrefixSeg {
		return MSG_INVILID, fmt.Errorf("Unsupport db %s", db)
	}
	dbPrefix := strings.Join(s[:nPrefixSeg], "_")
	appID := GetMeterID(dbPrefix)

	var msgType MessageType
	switch appID {
	case USAGE_ID:
		msgType = MSG_USAGE
	case PERF_ID:
		msgType = MSG_PERF
	case GEO_ID:
		msgType = MSG_GEO
	case FLOW_ID:
		msgType = MSG_FLOW
	case TYPE_ID:
		msgType = MSG_TYPE
	case FPS_ID:
		msgType = MSG_FPS
	case LOG_USAGE_ID:
		msgType = MSG_LOG_USAGE
	// 从influxdb streaming读取vtap_usage的数据时，会使用MSG_VTAP_SIMPLE消息打包成doc, 而不用MSG_VTAP_USAGE
	case VTAP_USAGE_ID:
		msgType = MSG_VTAP_SIMPLE
	default:
		return MSG_INVILID, fmt.Errorf("Unknown supported dbPrefix %s", dbPrefix)
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
	case MSG_USAGE:
		var m UsageMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case MSG_PERF:
		var m PerfMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case MSG_GEO:
		var m GeoMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case MSG_FLOW:
		var m FlowMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case MSG_TYPE:
		var m TypeMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case MSG_FPS:
		var m FPSMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	case MSG_LOG_USAGE:
		var m LogUsageMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	// 从influxdb streaming读取vtap_usage的数据时，使用MSG_VTAP_SIMPLE消息打包成doc
	case MSG_VTAP_SIMPLE:
		var m VTAPSimpleMeter
		m.Fill(columnIDs, columnValues)
		m.Encode(encoder)
	default:
		return fmt.Errorf("Unknown supported msgType %d", msgType)
	}

	encoder.WriteU32(0) // actionflag

	return nil
}
