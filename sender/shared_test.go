package sender

import (
	"encoding/binary"
	"reflect"
	"time"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	dt "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
)

var TEST_DATA []interface{}

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
	tag1 := f.NewTag(dt.IP | dt.L2EpcID | dt.L3EpcID)
	tag2 := f.NewTag(dt.L3Device | dt.MAC | dt.L3EpcID)
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
	TEST_DATA = append(TEST_DATA, &app.Document{Timestamp: 0x12345678, Tag: tag1, Meter: meter})
	TEST_DATA = append(TEST_DATA, &app.Document{Timestamp: 0x87654321, Tag: tag2, Meter: meter})
}

func receiverRoutine(nData, port int, ch chan []byte) {
	receiver, _ := zmq.NewPuller("*", port, 1000000, time.Minute, zmq.SERVER)
	for i := 0; i < nData; i++ {
		b, _ := receiver.Recv()
		ch <- b
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
