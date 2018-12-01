package messenger

import (
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
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
	msg.Tag = dt.TagToPB(tag)

	msg.Meter = &pb.Meter{}
	switch msgType {
	case MSG_USAGE:
		meter := doc.Meter.(*dt.UsageMeter)
		msg.Meter.Usage = dt.UsageMeterToPB(meter)
	case MSG_PERF:
		meter := doc.Meter.(*dt.PerfMeter)
		msg.Meter.Perf = dt.PerfMeterToPB(meter)
	case MSG_GEO:
		meter := doc.Meter.(*dt.GeoMeter)
		msg.Meter.Geo = dt.GeoMeterToPB(meter)
	case MSG_FLOW:
		meter := doc.Meter.(*dt.FlowMeter)
		msg.Meter.Flow = dt.FlowMeterToPB(meter)
	case MSG_CONSOLE_LOG:
		meter := doc.Meter.(*dt.ConsoleLogMeter)
		msg.Meter.ConsoleLog = dt.ConsoleLogMeterToPB(meter)
	case MSG_TYPE:
		meter := doc.Meter.(*dt.TypeMeter)
		msg.Meter.Type = dt.TypeMeterToPB(meter)
	case MSG_FPS:
		meter := doc.Meter.(*dt.FPSMeter)
		msg.Meter.Fps = dt.FPSMeterToPB(meter)
	}
	msg.ActionFlags = proto.Uint32(doc.ActionFlags)

	buf := bytes.Use(msg.Size())
	if _, err := msg.MarshalTo(buf); err != nil {
		return fmt.Errorf("Marshaling protobuf failed: %s", err)
	}

	return nil
}

// send to zero
func Encode(doc *app.Document, encoder *codec.SimpleEncoder) error {
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

	// Protocol:
	// optional uint32 timestamp = 1;
	// optional Tag tag = 2;
	// optional Meter meter = 3; // with uint8 type
	// optional uint32 action_flags = 4;

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
