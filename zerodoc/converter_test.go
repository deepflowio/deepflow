package zerodoc

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

func TestFullEqual(t *testing.T) {
	f := Field{
		IP:           0x0a2102c8,
		MAC:          0x020406080a0c,
		GroupID:      4,
		L2EpcID:      2,
		L3EpcID:      2,
		L2DeviceID:   3,
		L2DeviceType: VGatewayDevice,
		L3DeviceID:   5,
		L3DeviceType: VMDevice,
		Host:         0xac100197,

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
		L2DeviceType0: VGatewayDevice,
		L2DeviceID1:   6,
		L2DeviceType1: VMDevice,
		L3DeviceID0:   5,
		L3DeviceType0: VMDevice,
		L3DeviceID1:   6,
		L3DeviceType1: VMDevice,
		Host0:         0xac100197,
		Host1:         0xac100198,

		Direction:  ClientToServer,
		ACLGID:     3,
		VLANID:     123,
		Protocol:   layers.IPProtocolTCP,
		ServerPort: 1024,
		VTAP:       0x64646475,
		TAPType:    ToR,
		SubnetID:   10,
		ACLID:      12,
	}

	fromTag := f.NewTag(0xFFFFFFFFFFFFFFFF)
	pb := TagToPB(fromTag)
	toTag := AcquireTag()
	toTag.Field = AcquireField()
	PBToTag(pb, toTag)
	b := &utils.IntBuffer{}
	if fromTag.GetID(b) != toTag.GetID(b) {
		t.Error("Tag在序列化反序列化之后GetID与原Tag不一致")
	}
}

func TestPartialTagEqual(t *testing.T) {
	f := Field{
		IP:           0x0a2102c8,
		MAC:          0x020406080a0c,
		GroupID:      4,
		L2EpcID:      2,
		L3EpcID:      2,
		L2DeviceID:   3,
		L2DeviceType: VGatewayDevice,
		L3DeviceID:   5,
		L3DeviceType: VMDevice,
		Host:         0xac100197,

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
		L2DeviceType0: VGatewayDevice,
		L2DeviceID1:   6,
		L2DeviceType1: VMDevice,
		L3DeviceID0:   5,
		L3DeviceType0: VMDevice,
		L3DeviceID1:   6,
		L3DeviceType1: VMDevice,
		Host0:         0xac100197,
		Host1:         0xac100198,

		Direction:  ClientToServer,
		ACLGID:     3,
		VLANID:     123,
		Protocol:   layers.IPProtocolTCP,
		ServerPort: 1024,
		VTAP:       0x64646475,
		TAPType:    ToR,
		SubnetID:   10,
		ACLID:      12,
	}

	codes := [...]Code{
		IP | TAPType,
		L2EpcID | Protocol | TAPType,
		IP | Direction | Protocol | TAPType,
		GroupID | Protocol | TAPType,
		L3EpcID | ServerPort | TAPType,
		L3EpcIDPath | IPPath | L3DevicePath | Protocol,
		VLANID | Protocol | TAPType,
	}
	for _, code := range codes {
		fromTag := f.NewTag(code)
		pb := TagToPB(fromTag)
		toTag := AcquireTag()
		toTag.Field = AcquireField()
		PBToTag(pb, toTag)
		b := &utils.IntBuffer{}
		if fromTag.GetID(b) != toTag.GetID(b) {
			t.Errorf("Tag在序列化反序列化之后GetID与原Tag不一致, Code=%d", code)
		}
	}
}

func TestCustomTagEqual(t *testing.T) {
	f := Field{
		IP:           0x0a2102c8,
		MAC:          0x020406080a0c,
		GroupID:      4,
		L2EpcID:      2,
		L3EpcID:      2,
		L2DeviceID:   3,
		L2DeviceType: VGatewayDevice,
		L3DeviceID:   5,
		L3DeviceType: VMDevice,
		Host:         0xac100197,

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
		L2DeviceType0: VGatewayDevice,
		L2DeviceID1:   6,
		L2DeviceType1: VMDevice,
		L3DeviceID0:   5,
		L3DeviceType0: VMDevice,
		L3DeviceID1:   6,
		L3DeviceType1: VMDevice,
		Host0:         0xac100197,
		Host1:         0xac100198,

		Direction:  ClientToServer,
		ACLGID:     3,
		VLANID:     123,
		Protocol:   layers.IPProtocolTCP,
		ServerPort: 1024,
		VTAP:       0x64646475,
		TAPType:    ToR,
		SubnetID:   10,
		ACLID:      12,
	}
	f.AddCustomField(Country, "country", "CHN")
	f.AddCustomField(Region, "region", "Beijing")
	f.AddCustomField(ISPCode, "isp", "CHINAMOBILE")

	codes := [...]Code{
		IP | TAPType,
		IP | TAPType | Country | Region,
		IP | TAPType | Country | Region | ISPCode,
	}
	for _, code := range codes {
		fromTag := f.NewTag(code)
		pb := TagToPB(fromTag)
		toTag := AcquireTag()
		toTag.Field = AcquireField()
		PBToTag(pb, toTag)
		b := &utils.IntBuffer{}
		if fromTag.GetID(b) != toTag.GetID(b) {
			t.Errorf("Tag在序列化反序列化之后GetID与原Tag不一致, Code=%d", code)
		}
	}
}

func TestUsageMeterEqual(t *testing.T) {
	fromMeter := &UsageMeter{
		UsageMeterSum: UsageMeterSum{
			SumPacketTx: 1,
			SumPacketRx: 2,
			SumPacket:   3,
			SumBitTx:    4,
			SumBitRx:    5,
			SumBit:      9,
		},
		UsageMeterMax: UsageMeterMax{
			MaxPacketTx: 123,
			MaxPacketRx: 321,
			MaxPacket:   444,
			MaxBitTx:    456,
			MaxBitRx:    654,
			MaxBit:      1110,
		},
	}
	pb := UsageMeterToPB(fromMeter)
	toMeter := AcquireUsageMeter()
	PBToUsageMeter(pb, toMeter)
	if !reflect.DeepEqual(fromMeter, toMeter) {
		t.Error("Meter在序列化反序列化之后与原Meter不一致")
	}
}

func TestPerfMeterEqual(t *testing.T) {
	fromMeter := &PerfMeter{
		PerfMeterSum: PerfMeterSum{
			SumFlowCount:         1,
			SumClosedFlowCount:   2,
			SumRetransFlowCount:  3,
			SumHalfOpenFlowCount: 4,
			SumPacketTx:          1234,
			SumPacketRx:          4321,
			SumRetransCntTx:      13,
			SumRetransCntRx:      14,

			SumRTTSyn:     4,
			SumRTTAvg:     5,
			SumARTAvg:     8,
			SumRTTSynFlow: 6,
			SumRTTAvgFlow: 7,
			SumARTAvgFlow: 9,

			SumZeroWndCntTx: 16,
			SumZeroWndCntRx: 17,
		},
		PerfMeterMax: PerfMeterMax{
			MaxRTTSyn: 27,
			MaxRTTAvg: 28,
			MaxARTAvg: 31,
		},
		PerfMeterMin: PerfMeterMin{
			MinRTTSyn: 29,
			MinRTTAvg: 30,
			MinARTAvg: 32,
		},
	}
	pb := PerfMeterToPB(fromMeter)
	toMeter := AcquirePerfMeter()
	PBToPerfMeter(pb, toMeter)
	if !reflect.DeepEqual(fromMeter, toMeter) {
		t.Error("Meter在序列化反序列化之后与原Meter不一致")
	}
}

func TestGeoMeterEqual(t *testing.T) {
	fromMeter := &GeoMeter{
		SumClosedFlowCount:    1,
		SumAbnormalFlowCount:  2,
		SumClosedFlowDuration: time.Second,
		SumPacketTx:           1234,
		SumPacketRx:           4321,
		SumBitTx:              12345,
		SumBitRx:              54321,
	}
	pb := GeoMeterToPB(fromMeter)
	toMeter := AcquireGeoMeter()
	PBToGeoMeter(pb, toMeter)
	if !reflect.DeepEqual(fromMeter, toMeter) {
		t.Error("Meter在序列化反序列化之后与原Meter不一致")
	}
}

func TestFPSMeterEqual(t *testing.T) {
	fromMeter := &FPSMeter{
		SumFlowCount:       1,
		SumNewFlowCount:    2,
		SumClosedFlowCount: 3,

		MaxFlowCount:    19,
		MaxNewFlowCount: 20,
	}
	pb := FPSMeterToPB(fromMeter)
	toMeter := AcquireFPSMeter()
	PBToFPSMeter(pb, toMeter)
	if !reflect.DeepEqual(fromMeter, toMeter) {
		t.Error("Meter在序列化反序列化之后与原Meter不一致")
	}
}

func TestFlowMeterEqual(t *testing.T) {
	fromMeter := &FlowMeter{
		SumFlowCount:       1,
		SumNewFlowCount:    2,
		SumClosedFlowCount: 3,
	}
	pb := FlowMeterToPB(fromMeter)
	toMeter := AcquireFlowMeter()
	PBToFlowMeter(pb, toMeter)
	if !reflect.DeepEqual(fromMeter, toMeter) {
		t.Error("Meter在序列化反序列化之后与原Meter不一致")
	}
}

func TestConsoleLogMeterEqual(t *testing.T) {
	fromMeter := &ConsoleLogMeter{
		SumPacketTx:           1234,
		SumPacketRx:           4321,
		SumClosedFlowCount:    1,
		SumClosedFlowDuration: time.Second,
	}
	pb := ConsoleLogMeterToPB(fromMeter)
	toMeter := AcquireConsoleLogMeter()
	PBToConsoleLogMeter(pb, toMeter)
	if !reflect.DeepEqual(fromMeter, toMeter) {
		t.Error("Meter在序列化反序列化之后与原Meter不一致")
	}
}

func TestTypeMeterEqual(t *testing.T) {
	fromMeter := &TypeMeter{
		SumCountL0S1S:  4,
		SumCountL1S5S:  5,
		SumCountL5S10S: 6,
		SumCountL10S1M: 7,
		SumCountL1M1H:  8,
		SumCountL1H:    9,

		SumCountE0K10K:   10,
		SumCountE10K100K: 11,
		SumCountE100K1M:  12,
		SumCountE1M100M:  13,
		SumCountE100M1G:  14,
		SumCountE1G:      15,

		SumCountTClientRst:       16,
		SumCountTClientHalfOpen:  17,
		SumCountTClientHalfClose: 18,
		SumCountTServerRst:       19,
		SumCountTServerHalfOpen:  20,
		SumCountTServerHalfClose: 21,
	}
	pb := TypeMeterToPB(fromMeter)
	toMeter := AcquireTypeMeter()
	PBToTypeMeter(pb, toMeter)
	if !reflect.DeepEqual(fromMeter, toMeter) {
		t.Error("Meter在序列化反序列化之后与原Meter不一致")
	}
}
