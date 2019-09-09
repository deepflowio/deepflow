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

// send to zero
// Protocol:
//     version     uint32
//     sequence    uint32
//     timestamp   uint32
//     tag         Tag (bytes)
//     meterType   uint8
//     meter       Meter (bytes)
//     actionFlags uint32
func Encode(sequence uint32, doc *app.Document, encoder *codec.SimpleEncoder) error {
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
	case *VTAPUsageEdgeMeter:
		msgType = MSG_VTAP_USAGE_EDGE
	case *VTAPSimpleMeter:
		msgType = MSG_VTAP_SIMPLE
	default:
		return fmt.Errorf("Unknown supported type %T", v)
	}

	encoder.WriteU32(app.VERSION)
	encoder.WriteU32(sequence)
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
	case MSG_VTAP_USAGE_EDGE:
		meter = doc.Meter.(*VTAPUsageEdgeMeter)
	case MSG_VTAP_SIMPLE:
		meter = doc.Meter.(*VTAPSimpleMeter)
	}
	meter.Encode(encoder)

	encoder.WriteU32(doc.ActionFlags)

	return nil
}

// 由于trident等将多个doc合并为1个块进行发送， 只设置第一个doc的sequence即可
func SetSequence(sequence uint32, chunk []byte) {
	// 先偏移4个字节的VERSION字段
	binary.LittleEndian.PutUint32(chunk[4:], sequence)
}

func GetSequence(chunk []byte) uint32 {
	// 先偏移4个字节的VERSION字段
	return binary.LittleEndian.Uint32(chunk[4:])
}

// The return Document, must call app.ReleaseDocument to release after used
func Decode(decoder *codec.SimpleDecoder) (*app.Document, error) {
	if decoder == nil {
		return nil, errors.New("No input decoder")
	}

	if version := decoder.ReadU32(); version != app.VERSION {
		return nil, errors.New(fmt.Sprintf("message version incorrect, expect %d, found %d.", app.VERSION, version))
	}
	decoder.ReadU32() // sequence

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
	case MSG_VTAP_USAGE_EDGE:
		m := AcquireVTAPUsageEdgeMeter()
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
	if len(s) < 2 {
		return MSG_INVILID, fmt.Errorf("Unsupport db %s", db)
	}
	dbPrefix := strings.Join(s[:2], "_")

	var msgType MessageType
	switch dbPrefix {
	case "df_usage":
		msgType = MSG_USAGE
	case "df_perf":
		msgType = MSG_PERF
	case "df_geo":
		msgType = MSG_GEO
	case "df_flow":
		msgType = MSG_FLOW
	case "df_type":
		msgType = MSG_TYPE
	case "df_fps":
		msgType = MSG_FPS
	case "log_usage":
		msgType = MSG_LOG_USAGE
	// 从influxdb streaming读取vtap_usage的数据时，会使用MSG_VTAP_SIMPLE消息打包成doc, 而不用MSG_VTAP_USAGE
	case "vtap_usage":
		msgType = MSG_VTAP_SIMPLE
	default:
		return MSG_INVILID, fmt.Errorf("Unknown supported dbPrefix %s", dbPrefix)
	}

	return msgType, nil
}

// send to reciter
// Protocol:
//     version     uint32
//     sequence    uint32
//     timestamp   uint32
//     tag         Tag (bytes)
//     meterType   uint8
//     meter       Meter (bytes)
//     actionFlags uint32
func EncodeRow(tag *Tag, msgType MessageType, isTag []bool, columnNames []string, columnValues []interface{}, encoder *codec.SimpleEncoder) error {
	encoder.WriteU32(app.VERSION) // version
	encoder.WriteU32(0)           // sequence

	if timestamp, ok := columnValues[0].(time.Time); ok {
		encoder.WriteU32(uint32(timestamp.Unix())) // timestamp
	} else {
		return fmt.Errorf("Unknown timestamp %v", columnValues[0])
	}

	tag.FillValues(isTag, columnNames, columnValues)
	tag.Encode(encoder)

	encoder.WriteU8(uint8(msgType))

	switch msgType {
	case MSG_USAGE:
		var m UsageMeter
		m.Fill(isTag, columnNames, columnValues)
		m.Encode(encoder)
	case MSG_PERF:
		var m PerfMeter
		m.Fill(isTag, columnNames, columnValues)
		m.Encode(encoder)
	case MSG_GEO:
		var m GeoMeter
		m.Fill(isTag, columnNames, columnValues)
		m.Encode(encoder)
	case MSG_FLOW:
		var m FlowMeter
		m.Fill(isTag, columnNames, columnValues)
		m.Encode(encoder)
	case MSG_TYPE:
		var m TypeMeter
		m.Fill(isTag, columnNames, columnValues)
		m.Encode(encoder)
	case MSG_FPS:
		var m FPSMeter
		m.Fill(isTag, columnNames, columnValues)
		m.Encode(encoder)
	case MSG_LOG_USAGE:
		var m LogUsageMeter
		m.Fill(isTag, columnNames, columnValues)
		m.Encode(encoder)
	// 从influxdb streaming读取vtap_usage的数据时，使用MSG_VTAP_SIMPLE消息打包成doc
	case MSG_VTAP_SIMPLE:
		var m VTAPSimpleMeter
		m.Fill(isTag, columnNames, columnValues)
		m.Encode(encoder)
	default:
		return fmt.Errorf("Unknown supported msgType %d", msgType)
	}

	encoder.WriteU32(0) // actionflag

	return nil
}
