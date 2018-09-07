package sender

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/platform/droplet-mapreduce/pkg/api"
	dt "gitlab.x.lan/platform/droplet-mapreduce/pkg/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
)

var TEST_DATA []interface{}

func init() {
	TEST_DATA = make([]interface{}, 0, 10)
	f := dt.Field{
		IP:           "10.33.2.200",
		MAC:          "02:04:06:08:0a:0c",
		GroupID:      4,
		L2EpcID:      2,
		L3EpcID:      2,
		L2DeviceID:   3,
		L2DeviceType: dt.VGatewayDevice,
		L3DeviceID:   5,
		L3DeviceType: dt.VMDevice,

		IP0:           "10.33.2.200",
		IP1:           "10.33.2.202",
		MAC0:          "02:04:06:08:0a:0c",
		MAC1:          "02:03:04:05:06:07",
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

		Direction:  dt.ClientToServer,
		PolicyID:   3,
		VLANID:     123,
		Protocol:   layers.IPProtocolTCP,
		ServerPort: 1024,
		Host:       "172.16.1.151",
		VTAP:       "100.100.100.133",
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
	TEST_DATA = append(TEST_DATA, &api.Document{Timestamp: 0x12345678, Tag: tag1, Meter: meter})
	TEST_DATA = append(TEST_DATA, &api.Document{Timestamp: 0x87654321, Tag: tag2, Meter: meter})
}

func receiverRoutine(nData, port int, ch chan []byte) {
	receiver, _ := zmq.NewPuller("*", port, 1000000, time.Minute, zmq.SERVER)
	for i := 0; i < nData; i++ {
		b, _ := receiver.Recv()
		ch <- b
	}
	close(ch)
}

func checkDocument(t *testing.T, doc, other *api.Document) {

	if doc.Timestamp != other.Timestamp {
		t.Error("Timestamp在序列化前后不匹配")
	}

	oldTag := doc.Tag.(*dt.Tag)
	newTag := other.Tag.(*dt.Tag)
	if !oldTag.Equal(newTag) {
		t.Error("Tag在序列化前后不匹配")
	}

	if !reflect.DeepEqual(doc.Meter, other.Meter) {
		t.Error("Meter在序列化前后不匹配")
	}
}
