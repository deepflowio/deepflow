package messenger

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/protobuf"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	dt "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	pb "gitlab.x.lan/yunshan/message/zero"
)

func TestMarshal(t *testing.T) {
	f := dt.Field{
		IP:           0x0a2102c8,
		GroupID:      4,
		L3EpcID:      2,
		L3DeviceID:   5,
		L3DeviceType: dt.VMDevice,

		IP1:           0x0a2102ca,
		GroupID1:      2,
		L3EpcID1:      datatype.EPC_FROM_DEEPFLOW,
		L3DeviceID1:   6,
		L3DeviceType1: dt.VMDevice,

		Direction:  dt.ClientToServer,
		ACLGID:     3,
		VLANID:     123,
		Protocol:   layers.IPProtocolTCP,
		ServerPort: 1024,
		Host:       0xac100197,
		TAPType:    dt.ToR,
	}
	tag := f.NewTag(dt.IP | dt.L3EpcID)
	meter := &dt.UsageMeter{
		SumPacketTx: 1,
		SumPacketRx: 2,
		SumBitTx:    4,
		SumBitRx:    5,
	}
	doc := &app.Document{Timestamp: 0x12345678, Tag: tag, Meter: meter}
	bytes := utils.AcquireByteBuffer()
	Marshal(doc, bytes)
	newDoc, _ := unmarshal(bytes.Bytes())

	if doc.Timestamp != newDoc.Timestamp {
		t.Error("Timestamp在序列化前后不匹配")
	}

	oldTag := doc.Tag.(*dt.Tag)
	newTag := newDoc.Tag.(*dt.Tag)
	e := &codec.SimpleEncoder{}
	if oldTag.GetID(e) != newTag.GetID(e) {
		t.Error("Tag在序列化前后GetID不匹配")
	}

	if !reflect.DeepEqual(doc.Meter, newDoc.Meter) {
		t.Error("Meter在序列化前后不匹配")
	}
}

func unmarshal(b []byte) (*app.Document, error) {
	if b == nil {
		return nil, errors.New("No input byte")
	}

	msg := &pb.ZeroDocument{}
	if err := msg.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("Unmarshaling protobuf failed: %s", err)
	}

	doc := &app.Document{}
	doc.Timestamp = msg.GetTimestamp()
	doc.Tag = dt.AcquireTag()
	doc.Tag.(*dt.Tag).Field = dt.AcquireField()
	protobuf.PBToTag(msg.GetTag(), doc.Tag.(*dt.Tag))
	meter := msg.GetMeter()
	switch {
	case meter.GetUsage() != nil:
		m := dt.AcquireUsageMeter()
		protobuf.PBToUsageMeter(meter.GetUsage(), m)
		doc.Meter = m
	case meter.GetPerf() != nil:
		m := dt.AcquirePerfMeter()
		protobuf.PBToPerfMeter(meter.GetPerf(), m)
		doc.Meter = m
	case meter.GetGeo() != nil:
		m := dt.AcquireGeoMeter()
		protobuf.PBToGeoMeter(meter.GetGeo(), m)
		doc.Meter = m
	case meter.GetFlow() != nil:
		m := dt.AcquireFlowMeter()
		protobuf.PBToFlowMeter(meter.GetFlow(), m)
		doc.Meter = m
	case meter.GetType() != nil:
		m := dt.AcquireTypeMeter()
		protobuf.PBToTypeMeter(meter.GetType(), m)
		doc.Meter = m
	case meter.GetFps() != nil:
		m := dt.AcquireFPSMeter()
		protobuf.PBToFPSMeter(meter.GetFps(), m)
		doc.Meter = m
	}
	doc.ActionFlags = msg.GetActionFlags()

	return doc, nil
}
