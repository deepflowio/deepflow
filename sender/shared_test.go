package sender

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	dt "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
)

var TEST_DATA []interface{}

func decode(b []byte) (*app.Document, error) {
	if b == nil {
		return nil, errors.New("No input byte")
	}

	decoder := &codec.SimpleDecoder{}
	decoder.Init(b)

	doc := &app.Document{}
	decoder.ReadU64() // sequence
	decoder.ReadU32() // hash
	doc.Timestamp = decoder.ReadU32()
	doc.Tag = dt.AcquireTag()
	doc.Tag.(*dt.Tag).Field = dt.AcquireField()
	doc.Tag.(*dt.Tag).Decode(decoder)

	meterType := dt.MessageType(decoder.ReadU8())
	var m app.Meter
	switch meterType {
	case dt.MSG_USAGE:
		m = dt.AcquireUsageMeter()
	case dt.MSG_PERF:
		m = dt.AcquirePerfMeter()
	case dt.MSG_GEO:
		m = dt.AcquireGeoMeter()
	case dt.MSG_FLOW:
		m = dt.AcquireFlowMeter()
	case dt.MSG_TYPE:
		m = dt.AcquireTypeMeter()
	case dt.MSG_FPS:
		m = dt.AcquireFPSMeter()
	}
	doc.Meter = m
	m.Decode(decoder)
	doc.Flags = app.DocumentFlag(decoder.ReadU32())

	if decoder.Failed() {
		return nil, fmt.Errorf("Unmarshaling protobuf failed")
	}
	return doc, nil
}

func init() {
	TEST_DATA = make([]interface{}, 0, 10)
	f := dt.Field{
		IP:           binary.BigEndian.Uint32([]byte{10, 33, 2, 200}),
		GroupID:      4,
		L3EpcID:      2,
		L3DeviceID:   5,
		L3DeviceType: dt.VMDevice,
		HostID:       110,

		IP1:           binary.BigEndian.Uint32([]byte{10, 33, 2, 202}),
		GroupID1:      2,
		L3EpcID1:      datatype.EPC_FROM_DEEPFLOW,
		L3DeviceID1:   6,
		L3DeviceType1: dt.VMDevice,
		HostID1:       111,

		Direction:  dt.ClientToServer,
		VLANID:     123,
		Protocol:   layers.IPProtocolTCP,
		ServerPort: 1024,
		TAPType:    dt.ToR,
	}
	meter := &dt.UsageMeter{
		SumPacketTx: 1,
		SumPacketRx: 2,
		SumBitTx:    4,
		SumBitRx:    5,
	}
	doc1 := app.AcquireDocument()
	doc1.Timestamp = 0x12345678
	doc1.Tag = f.NewTag(dt.IP | dt.L3EpcID)
	doc1.Meter = meter.Clone()
	TEST_DATA = append(TEST_DATA, doc1)
	doc2 := app.AcquireDocument()
	doc2.Timestamp = 0x87654321
	doc2.Tag = f.NewTag(dt.L3Device | dt.L3EpcID)
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
		newDoc.Flags = doc.Flags
		testData = append(testData, newDoc)
	}
	return testData
}

func receiverRoutine(nData int, ip string, port int, ch chan *codec.SimpleEncoder) {
	var receiver zmq.Receiver
	if ip == "" || ip == "*" {
		receiver, _ = zmq.NewPuller("*", port, 1000000, time.Minute, zmq.SERVER)
	} else {
		receiver, _ = zmq.NewPuller(ip, port, 1000000, time.Minute, zmq.CLIENT)
	}
	for i := 0; i < nData; i++ {
		b, _ := receiver.Recv()
		encoder := codec.AcquireSimpleEncoder()
		encoder.WriteRawString(string(b))
		ch <- encoder
	}
	close(ch)
}

func documentEqual(doc, other *app.Document) bool {
	if doc.Timestamp != other.Timestamp {
		return false
	}

	oldTag := doc.Tag.(*dt.Tag)
	newTag := other.Tag.(*dt.Tag)
	e := &codec.SimpleEncoder{}
	if oldTag.GetID(e) != newTag.GetID(e) {
		return false
	}

	if !reflect.DeepEqual(doc.Meter, other.Meter) {
		return false
	}

	return true
}
