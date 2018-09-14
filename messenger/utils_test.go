package messenger

import (
	"reflect"
	"testing"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/app"
	dt "gitlab.x.lan/yunshan/droplet-libs/zerodoc"
)

func TestMarshal(t *testing.T) {
	f := dt.Field{
		IP:           0x0a2102c8,
		MAC:          0x020406080a0c,
		GroupID:      4,
		L2EpcID:      2,
		L3EpcID:      2,
		L2DeviceID:   3,
		L2DeviceType: dt.VGatewayDevice,
		L3DeviceID:   5,
		L3DeviceType: dt.VMDevice,

		IP0:           0x0a2102c8,
		IP1:           0x0a2102ca,
		MAC0:          0x020406080a0c,
		MAC1:          0x020304050607,
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
		PolicyType: 3,
		PolicyID:   3,
		VLANID:     123,
		Protocol:   layers.IPProtocolTCP,
		ServerPort: 1024,
		Host:       0xac100197,
		VTAP:       0x64646475,
		TAPType:    dt.ToR,
	}
	tag := f.NewTag(dt.IP | dt.L2EpcID | dt.L3EpcID)
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
	doc := &app.Document{Timestamp: 0x12345678, Tag: tag, Meter: meter}
	bin, _ := Marshal(doc)
	newDoc, _ := Unmarshal(bin)

	if doc.Timestamp != newDoc.Timestamp {
		t.Error("Timestamp在序列化前后不匹配")
	}

	oldTag := doc.Tag.(*dt.Tag)
	newTag := newDoc.Tag.(*dt.Tag)
	if !oldTag.Equal(newTag) {
		t.Error("Tag在序列化前后不匹配")
	}

	if !reflect.DeepEqual(doc.Meter, newDoc.Meter) {
		t.Error("Meter在序列化前后不匹配")
	}
}
