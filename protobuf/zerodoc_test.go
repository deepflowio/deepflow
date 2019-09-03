package protobuf

import (
	"reflect"
	"testing"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/zerodoc"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

func TestFullEqual(t *testing.T) {
	f := Field{
		IP:           0x0a2102c8,
		GroupID:      4,
		L3EpcID:      2,
		L3DeviceID:   5,
		L3DeviceType: VMDevice,
		Host:         0xac100197,

		IP1:           0x0a2102ca,
		GroupID1:      2,
		L3EpcID1:      datatype.EPC_FROM_DEEPFLOW,
		L3DeviceID1:   6,
		L3DeviceType1: VMDevice,
		Host1:         0xac100198,

		Direction:  ClientToServer,
		ACLGID:     3,
		VLANID:     123,
		Protocol:   layers.IPProtocolTCP,
		ServerPort: 1024,
		TAPType:    ToR,
		SubnetID:   10,
	}

	fromTag := f.NewTag(0xFFFFFFFFFFFF)
	pb := TagToPB(fromTag)
	toTag := AcquireTag()
	toTag.Field = AcquireField()
	PBToTag(pb, toTag)
	e := &codec.SimpleEncoder{}
	if fromTag.GetID(e) != toTag.GetID(e) {
		t.Error("Tag在序列化反序列化之后GetID与原Tag不一致")
	}
}

func TestPartialTagEqual(t *testing.T) {
	f := Field{
		IP:           0x0a2102c8,
		GroupID:      4,
		L3EpcID:      2,
		L3DeviceID:   5,
		L3DeviceType: VMDevice,
		Host:         0xac100197,

		IP1:           0x0a2102ca,
		GroupID1:      2,
		L3EpcID1:      datatype.EPC_FROM_DEEPFLOW,
		L3DeviceID1:   6,
		L3DeviceType1: VMDevice,
		Host1:         0xac100198,

		Direction:  ClientToServer,
		ACLGID:     3,
		VLANID:     123,
		Protocol:   layers.IPProtocolTCP,
		ServerPort: 1024,
		TAPType:    ToR,
		SubnetID:   10,
	}

	codes := [...]Code{
		IP | TAPType,
		Protocol | TAPType,
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
		e := &codec.SimpleEncoder{}
		if fromTag.GetID(e) != toTag.GetID(e) {
			t.Errorf("Tag在序列化反序列化之后GetID与原Tag不一致, Code=%d", code)
		}
	}
}

func TestUsageMeterEqual(t *testing.T) {
	fromMeter := &UsageMeter{
		SumPacketTx: 1,
		SumPacketRx: 2,
		SumBitTx:    4,
		SumBitRx:    5,
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
		SumPacketTx: 1234,
		SumPacketRx: 4321,
		SumBitTx:    12345,
		SumBitRx:    54321,
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
		SumClosedFlowDuration: 1,
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
