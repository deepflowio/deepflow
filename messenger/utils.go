package messenger

import (
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"gitlab.x.lan/yunshan/droplet-libs/app"
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

	var msgType dt.MessageType
	switch v := doc.Meter.(type) {
	case *dt.UsageMeter:
		msgType = dt.MSG_USAGE
	case *dt.PerfMeter:
		msgType = dt.MSG_PERF
	case *dt.GeoMeter:
		msgType = dt.MSG_GEO
	case *dt.FlowMeter:
		msgType = dt.MSG_FLOW
	case *dt.ConsoleLogMeter:
		msgType = dt.MSG_CONSOLE_LOG
	case *dt.TypeMeter:
		msgType = dt.MSG_TYPE
	case *dt.FPSMeter:
		msgType = dt.MSG_FPS
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
	case dt.MSG_USAGE:
		meter := doc.Meter.(*dt.UsageMeter)
		msg.Meter.Usage = protobuf.UsageMeterToPB(meter)
	case dt.MSG_PERF:
		meter := doc.Meter.(*dt.PerfMeter)
		msg.Meter.Perf = protobuf.PerfMeterToPB(meter)
	case dt.MSG_GEO:
		meter := doc.Meter.(*dt.GeoMeter)
		msg.Meter.Geo = protobuf.GeoMeterToPB(meter)
	case dt.MSG_FLOW:
		meter := doc.Meter.(*dt.FlowMeter)
		msg.Meter.Flow = protobuf.FlowMeterToPB(meter)
	case dt.MSG_CONSOLE_LOG:
		meter := doc.Meter.(*dt.ConsoleLogMeter)
		msg.Meter.ConsoleLog = protobuf.ConsoleLogMeterToPB(meter)
	case dt.MSG_TYPE:
		meter := doc.Meter.(*dt.TypeMeter)
		msg.Meter.Type = protobuf.TypeMeterToPB(meter)
	case dt.MSG_FPS:
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
