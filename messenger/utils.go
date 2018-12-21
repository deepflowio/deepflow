package messenger

import (
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/protobuf"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	dt "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	pb "gitlab.x.lan/yunshan/message/zero"
)

// send to alarm
func Marshal(doc *app.Document, bytes *utils.ByteBuffer) error {
	if doc.Tag == nil || doc.Meter == nil {
		return errors.New("No tag or meter in document")
	}

	var msgType MessageType
	switch v := doc.Meter.(type) {
	case *dt.UsageMeter:
		msgType = MSG_USAGE
	case *dt.PerfMeter:
		msgType = MSG_PERF
	case *dt.GeoMeter:
		msgType = MSG_GEO
	case *dt.FlowMeter:
		msgType = MSG_FLOW
	case *dt.ConsoleLogMeter:
		msgType = MSG_CONSOLE_LOG
	case *dt.TypeMeter:
		msgType = MSG_TYPE
	case *dt.FPSMeter:
		msgType = MSG_FPS
	default:
		return fmt.Errorf("Unknown supported type %T", v)
	}

	msg := &pb.ZeroDocument{}
	msg.Timestamp = proto.Uint32(doc.Timestamp)

	var tag *dt.Tag
	tag, ok := doc.Tag.(*dt.Tag)
	if !ok {
		return fmt.Errorf("Unknown supported tag type %T", doc.Tag)
	}
	msg.Tag = protobuf.TagToPB(tag)

	msg.Meter = &pb.Meter{}
	switch msgType {
	case MSG_USAGE:
		meter := doc.Meter.(*dt.UsageMeter)
		msg.Meter.Usage = protobuf.UsageMeterToPB(meter)
	case MSG_PERF:
		meter := doc.Meter.(*dt.PerfMeter)
		msg.Meter.Perf = protobuf.PerfMeterToPB(meter)
	case MSG_GEO:
		meter := doc.Meter.(*dt.GeoMeter)
		msg.Meter.Geo = protobuf.GeoMeterToPB(meter)
	case MSG_FLOW:
		meter := doc.Meter.(*dt.FlowMeter)
		msg.Meter.Flow = protobuf.FlowMeterToPB(meter)
	case MSG_CONSOLE_LOG:
		meter := doc.Meter.(*dt.ConsoleLogMeter)
		msg.Meter.ConsoleLog = protobuf.ConsoleLogMeterToPB(meter)
	case MSG_TYPE:
		meter := doc.Meter.(*dt.TypeMeter)
		msg.Meter.Type = protobuf.TypeMeterToPB(meter)
	case MSG_FPS:
		meter := doc.Meter.(*dt.FPSMeter)
		msg.Meter.Fps = protobuf.FPSMeterToPB(meter)
	}
	msg.ActionFlags = proto.Uint32(doc.ActionFlags)

	buf := bytes.Use(msg.Size())
	if _, err := msg.MarshalTo(buf); err != nil {
		return fmt.Errorf("Marshaling protobuf failed: %s", err)
	}

	return nil
}

// send to zero
// Protocol:
//     sequence    uint32
//     hash        uint32
//     timestamp   uint32
//     tag         Tag (bytes)
//     meterType   uint8
//     meter       Meter (bytes)
//     actionFlags uint32
func Encode(sequence uint32, hash uint32, doc *app.Document, encoder *codec.SimpleEncoder) error {
	if doc.Tag == nil || doc.Meter == nil {
		return errors.New("No tag or meter in document")
	}
	encoder.Reset()

	var msgType MessageType
	switch v := doc.Meter.(type) {
	case *dt.UsageMeter:
		msgType = MSG_USAGE
	case *dt.PerfMeter:
		msgType = MSG_PERF
	case *dt.GeoMeter:
		msgType = MSG_GEO
	case *dt.FlowMeter:
		msgType = MSG_FLOW
	case *dt.ConsoleLogMeter:
		msgType = MSG_CONSOLE_LOG
	case *dt.TypeMeter:
		msgType = MSG_TYPE
	case *dt.FPSMeter:
		msgType = MSG_FPS
	default:
		return fmt.Errorf("Unknown supported type %T", v)
	}

	encoder.WriteU32(sequence)
	encoder.WriteU32(hash)
	encoder.WriteU32(doc.Timestamp)

	var tag *dt.Tag
	tag, ok := doc.Tag.(*dt.Tag)
	if !ok {
		return fmt.Errorf("Unknown supported tag type %T", doc.Tag)
	}
	tag.Encode(encoder)

	encoder.WriteU8(uint8(msgType))
	var meter app.Meter
	switch msgType {
	case MSG_USAGE:
		meter = doc.Meter.(*dt.UsageMeter)
	case MSG_PERF:
		meter = doc.Meter.(*dt.PerfMeter)
	case MSG_GEO:
		meter = doc.Meter.(*dt.GeoMeter)
	case MSG_FLOW:
		meter = doc.Meter.(*dt.FlowMeter)
	case MSG_CONSOLE_LOG:
		meter = doc.Meter.(*dt.ConsoleLogMeter)
	case MSG_TYPE:
		meter = doc.Meter.(*dt.TypeMeter)
	case MSG_FPS:
		meter = doc.Meter.(*dt.FPSMeter)
	}
	meter.Encode(encoder)

	encoder.WriteU32(doc.ActionFlags)

	return nil
}

// TODO: 增加Decode函数供Zero使用

func EncodeVTAP(doc *app.Document, encoder *codec.SimpleEncoder) error {
	if doc.Tag == nil || doc.Meter == nil {
		return errors.New("No tag or meter in document")
	}
	encoder.Reset()

	var msgType MessageType
	switch v := doc.Meter.(type) {
	case *dt.VTAPUsageMeter:
		msgType = MSG_VTAP_USAGE
	default:
		return fmt.Errorf("Unknown supported type %T", v)
	}

	encoder.WriteU32(doc.Timestamp)

	var tag *dt.Tag
	tag, ok := doc.Tag.(*dt.Tag)
	if !ok {
		return fmt.Errorf("Unknown supported tag type %T", doc.Tag)
	}
	tag.Encode(encoder)

	encoder.WriteU8(uint8(msgType))
	var meter app.Meter
	switch msgType {
	case MSG_VTAP_USAGE:
		meter = doc.Meter.(*dt.VTAPUsageMeter)
	}
	meter.Encode(encoder)

	return nil
}

func DecodeVTAP(b []byte) (*app.Document, error) {
	if b == nil {
		return nil, errors.New("No input byte")
	}

	decoder := &codec.SimpleDecoder{}
	decoder.Init(b)

	doc := app.AcquireDocument()

	doc.Timestamp = decoder.ReadU32()

	tag := dt.AcquireTag()
	tag.Field = dt.AcquireField()
	tag.Decode(decoder)
	doc.Tag = tag

	msgType := decoder.ReadU8()
	switch MessageType(msgType) {
	case MSG_VTAP_USAGE:
		m := dt.AcquireVTAPUsageMeter()
		m.Decode(decoder)
		doc.Meter = m
	default:
		return nil, fmt.Errorf("Error meter type %v", msgType)
	}

	if decoder.Failed() {
		return nil, errors.New("Decode failed")
	}
	return doc, nil
}
