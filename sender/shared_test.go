package sender

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	dt "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
	pb "gitlab.x.lan/yunshan/message/zero"
)

var TEST_DATA []interface{}

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
	dt.PBToTag(msg.GetTag(), doc.Tag.(*dt.Tag))
	meter := msg.GetMeter()
	switch {
	case meter.GetUsage() != nil:
		m := dt.AcquireUsageMeter()
		dt.PBToUsageMeter(meter.GetUsage(), m)
		doc.Meter = m
	case meter.GetPerf() != nil:
		m := dt.AcquirePerfMeter()
		dt.PBToPerfMeter(meter.GetPerf(), m)
		doc.Meter = m
	case meter.GetGeo() != nil:
		m := dt.AcquireGeoMeter()
		dt.PBToGeoMeter(meter.GetGeo(), m)
		doc.Meter = m
	case meter.GetFlow() != nil:
		m := dt.AcquireFlowMeter()
		dt.PBToFlowMeter(meter.GetFlow(), m)
		doc.Meter = m
	case meter.GetConsoleLog() != nil:
		m := dt.AcquireConsoleLogMeter()
		dt.PBToConsoleLogMeter(meter.GetConsoleLog(), m)
		doc.Meter = m
	case meter.GetType() != nil:
		m := dt.AcquireTypeMeter()
		dt.PBToTypeMeter(meter.GetType(), m)
		doc.Meter = m
	case meter.GetFps() != nil:
		m := dt.AcquireFPSMeter()
		dt.PBToFPSMeter(meter.GetFps(), m)
		doc.Meter = m
	}
	doc.ActionFlags = msg.GetActionFlags()

	return doc, nil
}

func init() {
	TEST_DATA = make([]interface{}, 0, 10)
	f := dt.Field{
		IP:           binary.BigEndian.Uint32([]byte{10, 33, 2, 200}),
		MAC:          binary.BigEndian.Uint64([]byte{2, 4, 6, 8, 10, 12, 0, 0}),
		GroupID:      4,
		L2EpcID:      2,
		L3EpcID:      2,
		L2DeviceID:   3,
		L2DeviceType: dt.VGatewayDevice,
		L3DeviceID:   5,
		L3DeviceType: dt.VMDevice,
		Host:         binary.BigEndian.Uint32([]byte{172, 16, 1, 153}),

		IP0:           binary.BigEndian.Uint32([]byte{10, 33, 2, 200}),
		IP1:           binary.BigEndian.Uint32([]byte{10, 33, 2, 202}),
		MAC0:          binary.BigEndian.Uint64([]byte{2, 4, 6, 8, 10, 12, 0, 0}),
		MAC1:          binary.BigEndian.Uint64([]byte{2, 3, 4, 5, 6, 7, 0, 0}),
		GroupID0:      4,
		GroupID1:      2,
		L2EpcID0:      2,
		L2EpcID1:      -1,
		L3EpcID0:      2,
		L3EpcID1:      -1,
		L2DeviceID0:   3,
		L2DeviceType0: dt.VGatewayDevice,
		L2DeviceID1:   6,
		L2DeviceType1: dt.VMDevice,
		L3DeviceID0:   5,
		L3DeviceType0: dt.VMDevice,
		L3DeviceID1:   6,
		L3DeviceType1: dt.VMDevice,
		Host0:         binary.BigEndian.Uint32([]byte{172, 16, 1, 153}),
		Host1:         binary.BigEndian.Uint32([]byte{172, 16, 1, 154}),

		Direction:  dt.ClientToServer,
		VLANID:     123,
		Protocol:   layers.IPProtocolTCP,
		ServerPort: 1024,
		VTAP:       binary.BigEndian.Uint32([]byte{100, 100, 100, 233}),
		TAPType:    dt.ToR,
	}
	meter := &dt.UsageMeter{
		UsageMeterSum: dt.UsageMeterSum{
			SumPacketTx: 1,
			SumPacketRx: 2,
			SumPacket:   3,
			SumBitTx:    4,
			SumBitRx:    5,
			SumBit:      9,
		},
		UsageMeterMax: dt.UsageMeterMax{
			MaxPacketTx: 123,
			MaxPacketRx: 321,
			MaxPacket:   444,
			MaxBitTx:    456,
			MaxBitRx:    654,
			MaxBit:      1110,
		},
	}
	doc1 := app.AcquireDocument()
	doc1.Timestamp = 0x12345678
	doc1.Tag = f.NewTag(dt.IP | dt.L2EpcID | dt.L3EpcID)
	doc1.Meter = meter.Clone()
	TEST_DATA = append(TEST_DATA, doc1)
	doc2 := app.AcquireDocument()
	doc2.Timestamp = 0x87654321
	doc2.Tag = f.NewTag(dt.L3Device | dt.MAC | dt.L3EpcID)
	doc2.Meter = meter.Clone()
	TEST_DATA = append(TEST_DATA, doc2)
}

func dupTestData() []interface{} {
	testData := make([]interface{}, 0, len(TEST_DATA))
	for _, ref := range TEST_DATA {
		doc := ref.(*app.Document)
		newDoc := app.AcquireDocument()
		newDoc.Timestamp = doc.Timestamp
		newDoc.Tag = dt.CloneTag(doc.Tag.(*dt.Tag))
		newDoc.Meter = doc.Meter.Clone()
		newDoc.ActionFlags = doc.ActionFlags
		testData = append(testData, newDoc)
	}
	return testData
}

func receiverRoutine(nData int, ip string, port int, ch chan *utils.ByteBuffer) {
	var receiver zmq.Receiver
	if ip == "" || ip == "*" {
		receiver, _ = zmq.NewPuller("*", port, 1000000, time.Minute, zmq.SERVER)
	} else {
		receiver, _ = zmq.NewPuller(ip, port, 1000000, time.Minute, zmq.CLIENT)
	}
	for i := 0; i < nData; i++ {
		b, _ := receiver.Recv()
		bytes := utils.AcquireByteBuffer()
		copy(bytes.Use(len(b)), b)
		ch <- bytes
	}
	close(ch)
}

func documentEqual(doc, other *app.Document) bool {

	if doc.Timestamp != other.Timestamp {
		return false
	}

	oldTag := doc.Tag.(*dt.Tag)
	newTag := other.Tag.(*dt.Tag)
	b := &utils.IntBuffer{}
	if oldTag.GetID(b) != newTag.GetID(b) {
		return false
	}

	if !reflect.DeepEqual(doc.Meter, other.Meter) {
		return false
	}

	return true
}
