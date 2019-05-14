package protobuf

import (
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket/layers"
	. "gitlab.x.lan/yunshan/droplet-libs/zerodoc"

	pb "gitlab.x.lan/yunshan/message/zero"
)

func TagToPB(t *Tag) *pb.Tag {
	tag := &pb.Tag{
		Code: proto.Uint64(uint64(t.Code.RemoveIndex())),
	}

	if t.Code&IP != 0 {
		tag.Ip = proto.Uint32(t.IP)
	}
	if t.Code&GroupID != 0 {
		tag.GroupId = proto.Int32(int32(t.GroupID))
	}
	if t.Code&L2EpcID != 0 {
		tag.L2EpcId = proto.Int32(int32(t.L2EpcID))
	}
	if t.Code&L3EpcID != 0 {
		tag.L3EpcId = proto.Int32(int32(t.L3EpcID))
	}
	if t.Code&L2Device != 0 {
		tag.L2DeviceId = proto.Uint32(uint32(t.L2DeviceID))
		tag.L2DeviceType = pb.DeviceType(t.L2DeviceType).Enum()
	}
	if t.Code&L3Device != 0 {
		tag.L3DeviceId = proto.Uint32(uint32(t.L3DeviceID))
		tag.L3DeviceType = pb.DeviceType(t.L3DeviceType).Enum()
	}
	if t.Code&Host != 0 {
		tag.Host = proto.Uint32(t.Host)
	}

	if t.Code&IPPath != 0 {
		tag.Ip_0 = proto.Uint32(t.IP)
		tag.Ip_1 = proto.Uint32(t.IP1)
	}
	if t.Code&GroupIDPath != 0 {
		tag.GroupId_0 = proto.Int32(int32(t.GroupID))
		tag.GroupId_1 = proto.Int32(int32(t.GroupID1))
	}
	if t.Code&L2EpcIDPath != 0 {
		tag.L2EpcId_0 = proto.Int32(int32(t.L2EpcID))
		tag.L2EpcId_1 = proto.Int32(int32(t.L2EpcID1))
	}
	if t.Code&L3EpcIDPath != 0 {
		tag.L3EpcId_0 = proto.Int32(int32(t.L3EpcID))
		tag.L3EpcId_1 = proto.Int32(int32(t.L3EpcID1))
	}
	if t.Code&L2DevicePath != 0 {
		tag.L2DeviceId_0 = proto.Uint32(uint32(t.L2DeviceID))
		tag.L2DeviceType_0 = pb.DeviceType(t.L2DeviceType).Enum()
		tag.L2DeviceId_1 = proto.Uint32(uint32(t.L2DeviceID1))
		tag.L2DeviceType_1 = pb.DeviceType(t.L2DeviceType1).Enum()
	}
	if t.Code&L3DevicePath != 0 {
		tag.L3DeviceId_0 = proto.Uint32(uint32(t.L3DeviceID))
		tag.L3DeviceType_0 = pb.DeviceType(t.L3DeviceType).Enum()
		tag.L3DeviceId_1 = proto.Uint32(uint32(t.L3DeviceID1))
		tag.L3DeviceType_1 = pb.DeviceType(t.L3DeviceType1).Enum()
	}
	if t.Code&HostPath != 0 {
		tag.Host_0 = proto.Uint32(t.Host)
		tag.Host_1 = proto.Uint32(t.Host1)
	}

	if t.Code&Direction != 0 {
		tag.Direction = pb.Direction(t.Direction).Enum()
	}
	if t.Code&ACLGID != 0 {
		tag.AclGid = proto.Uint32(uint32(t.ACLGID))
	}
	if t.Code&VLANID != 0 {
		tag.VlanId = proto.Uint32(uint32(t.VLANID))
	}
	if t.Code&Protocol != 0 {
		tag.Protocol = proto.Uint32(uint32(t.Protocol))
	}
	if t.Code&ServerPort != 0 {
		tag.ServerPort = proto.Uint32(uint32(t.ServerPort))
	}
	if t.Code&TAPType != 0 {
		tag.TapType = proto.Uint32(uint32(t.TAPType))
	}
	if t.Code&SubnetID != 0 {
		tag.SubnetId = proto.Uint32(uint32(t.SubnetID))
	}
	if t.Code&ACLDirection != 0 {
		tag.AclDirection = pb.AclDirection(t.ACLDirection).Enum()
	}

	return tag
}

func PBToTag(t *pb.Tag, tag *Tag) {
	if tag == nil || tag.Field == nil {
		panic("tag或tag.Field为空")
	}
	tag.Code = Code(t.GetCode())

	if tag.Code&IP != 0 {
		tag.IP = t.GetIp()
	}
	if tag.Code&GroupID != 0 {
		tag.GroupID = int16(t.GetGroupId())
	}
	if tag.Code&L2EpcID != 0 {
		tag.L2EpcID = int16(t.GetL2EpcId())
	}
	if tag.Code&L3EpcID != 0 {
		tag.L3EpcID = int16(t.GetL3EpcId())
	}
	if tag.Code&L2Device != 0 {
		tag.L2DeviceID = uint16(t.GetL2DeviceId())
		tag.L2DeviceType = DeviceType(t.GetL2DeviceType())
	}
	if tag.Code&L3Device != 0 {
		tag.L3DeviceID = uint16(t.GetL3DeviceId())
		tag.L3DeviceType = DeviceType(t.GetL3DeviceType())
	}
	if tag.Code&Host != 0 {
		tag.Host = t.GetHost()
	}

	if tag.Code&IPPath != 0 {
		tag.IP = t.GetIp_0()
		tag.IP1 = t.GetIp_1()
	}
	if tag.Code&GroupIDPath != 0 {
		tag.GroupID = int16(t.GetGroupId_0())
		tag.GroupID1 = int16(t.GetGroupId_1())
	}
	if tag.Code&L2EpcIDPath != 0 {
		tag.L2EpcID = int16(t.GetL2EpcId_0())
		tag.L2EpcID1 = int16(t.GetL2EpcId_1())
	}
	if tag.Code&L3EpcIDPath != 0 {
		tag.L3EpcID = int16(t.GetL3EpcId_0())
		tag.L3EpcID1 = int16(t.GetL3EpcId_1())
	}
	if tag.Code&L2DevicePath != 0 {
		tag.L2DeviceID = uint16(t.GetL2DeviceId_0())
		tag.L2DeviceType = DeviceType(t.GetL2DeviceType_0())
		tag.L2DeviceID1 = uint16(t.GetL2DeviceId_1())
		tag.L2DeviceType1 = DeviceType(t.GetL2DeviceType_1())
	}
	if tag.Code&L3DevicePath != 0 {
		tag.L3DeviceID = uint16(t.GetL3DeviceId_0())
		tag.L3DeviceType = DeviceType(t.GetL3DeviceType_0())
		tag.L3DeviceID1 = uint16(t.GetL3DeviceId_1())
		tag.L3DeviceType1 = DeviceType(t.GetL3DeviceType_1())
	}
	if tag.Code&HostPath != 0 {
		tag.Host = t.GetHost_0()
		tag.Host1 = t.GetHost_1()
	}

	if tag.Code&Direction != 0 {
		tag.Direction = DirectionEnum(t.GetDirection())
	}
	if tag.Code&ACLGID != 0 {
		tag.ACLGID = uint16(t.GetAclGid())
	}
	if tag.Code&VLANID != 0 {
		tag.VLANID = uint16(t.GetVlanId())
	}
	if tag.Code&Protocol != 0 {
		tag.Protocol = layers.IPProtocol(uint8(t.GetProtocol()))
	}
	if tag.Code&ServerPort != 0 {
		tag.ServerPort = uint16(t.GetServerPort())
	}
	if tag.Code&TAPType != 0 {
		tag.TAPType = TAPTypeEnum(t.GetTapType())
	}
	if tag.Code&SubnetID != 0 {
		tag.SubnetID = uint16(t.GetSubnetId())
	}
	if tag.Code&ACLDirection != 0 {
		tag.ACLDirection = ACLDirectionEnum(t.GetAclDirection())
	}
}

func UsageMeterToPB(m *UsageMeter) *pb.UsageMeter {
	return &pb.UsageMeter{
		Sum: &pb.UsageStats{
			PacketTx: proto.Uint64(m.SumPacketTx),
			PacketRx: proto.Uint64(m.SumPacketRx),
			Packet:   proto.Uint64(m.SumPacketTx + m.SumPacketRx),
			BitTx:    proto.Uint64(m.SumBitTx),
			BitRx:    proto.Uint64(m.SumBitRx),
			Bit:      proto.Uint64(m.SumBitTx + m.SumBitRx),
		},
		Max: &pb.UsageStats{
			PacketTx: proto.Uint64(m.MaxPacketTx),
			PacketRx: proto.Uint64(m.MaxPacketRx),
			Packet:   proto.Uint64(m.MaxPacket),
			BitTx:    proto.Uint64(m.MaxBitTx),
			BitRx:    proto.Uint64(m.MaxBitRx),
			Bit:      proto.Uint64(m.MaxBit),
		},
	}
}

func PBToUsageMeter(m *pb.UsageMeter, meter *UsageMeter) {
	if meter == nil {
		panic("meter为空")
	}

	sum := m.GetSum()
	meter.SumPacketTx = sum.GetPacketTx()
	meter.SumPacketRx = sum.GetPacketRx()
	meter.SumBitTx = sum.GetBitTx()
	meter.SumBitRx = sum.GetBitRx()

	max := m.GetMax()
	meter.MaxPacketTx = max.GetPacketTx()
	meter.MaxPacketRx = max.GetPacketRx()
	meter.MaxPacket = max.GetPacket()
	meter.MaxBitTx = max.GetBitTx()
	meter.MaxBitRx = max.GetBitRx()
	meter.MaxBit = max.GetBit()
}

func PerfMeterToPB(m *PerfMeter) *pb.PerfMeter {
	sum := PerfMeterSumToPB(&m.PerfMeterSum)
	max := PerfMeterMaxToPB(&m.PerfMeterMax)
	min := PerfMeterMinToPB(&m.PerfMeterMin)
	return &pb.PerfMeter{
		Sum: sum,
		Max: max,
		Min: min,
	}
}

func PBToPerfMeter(m *pb.PerfMeter, meter *PerfMeter) {
	if meter == nil {
		panic("meter为空")
	}

	pbToPerfMeterSum(m.GetSum(), &meter.PerfMeterSum)
	pbToPerfMeterMax(m.GetMax(), &meter.PerfMeterMax)
	pbToPerfMeterMin(m.GetMin(), &meter.PerfMeterMin)
}

func PerfMeterSumToPB(m *PerfMeterSum) *pb.PerfStats {
	return &pb.PerfStats{
		FlowCount:         proto.Uint64(m.SumFlowCount),
		ClosedFlowCount:   proto.Uint64(m.SumClosedFlowCount),
		RetransFlowCount:  proto.Uint64(m.SumRetransFlowCount),
		HalfOpenFlowCount: proto.Uint64(m.SumHalfOpenFlowCount),
		PacketTx:          proto.Uint64(m.SumPacketTx),
		PacketRx:          proto.Uint64(m.SumPacketRx),
		RetransCntTx:      proto.Uint64(m.SumRetransCntTx),
		RetransCntRx:      proto.Uint64(m.SumRetransCntRx),

		RttSyn:     proto.Uint64(uint64(m.SumRTTSyn)),
		RttAvg:     proto.Uint64(uint64(m.SumRTTAvg)),
		ArtAvg:     proto.Uint64(uint64(m.SumARTAvg)),
		RttSynFlow: proto.Uint64(m.SumRTTSynFlow),
		RttAvgFlow: proto.Uint64(m.SumRTTAvgFlow),
		ArtAvgFlow: proto.Uint64(m.SumARTAvgFlow),

		ZeroWndCntTx: proto.Uint64(m.SumZeroWndCntTx),
		ZeroWndCntRx: proto.Uint64(m.SumZeroWndCntRx),
	}
}

func pbToPerfMeterSum(m *pb.PerfStats, meter *PerfMeterSum) {
	meter.SumFlowCount = m.GetFlowCount()
	meter.SumClosedFlowCount = m.GetClosedFlowCount()
	meter.SumRetransFlowCount = m.GetRetransFlowCount()
	meter.SumHalfOpenFlowCount = m.GetHalfOpenFlowCount()
	meter.SumPacketTx = m.GetPacketTx()
	meter.SumPacketRx = m.GetPacketRx()
	meter.SumRetransCntTx = m.GetRetransCntTx()
	meter.SumRetransCntRx = m.GetRetransCntRx()

	meter.SumRTTSyn = time.Duration(m.GetRttSyn())
	meter.SumRTTAvg = time.Duration(m.GetRttAvg())
	meter.SumARTAvg = time.Duration(m.GetArtAvg())
	meter.SumRTTSynFlow = m.GetRttSynFlow()
	meter.SumRTTAvgFlow = m.GetRttAvgFlow()
	meter.SumARTAvgFlow = m.GetArtAvgFlow()

	meter.SumZeroWndCntTx = m.GetZeroWndCntTx()
	meter.SumZeroWndCntRx = m.GetZeroWndCntRx()
}

func PerfMeterMaxToPB(m *PerfMeterMax) *pb.RttStats {
	return &pb.RttStats{
		RttSyn: proto.Uint64(uint64(m.MaxRTTSyn)),
		RttAvg: proto.Uint64(uint64(m.MaxRTTAvg)),
		ArtAvg: proto.Uint64(uint64(m.MaxARTAvg)),
	}
}

func pbToPerfMeterMax(m *pb.RttStats, meter *PerfMeterMax) {
	meter.MaxRTTSyn = time.Duration(m.GetRttSyn())
	meter.MaxRTTAvg = time.Duration(m.GetRttAvg())
	meter.MaxARTAvg = time.Duration(m.GetArtAvg())
}

func PerfMeterMinToPB(m *PerfMeterMin) *pb.RttStats {
	return &pb.RttStats{
		RttSyn: proto.Uint64(uint64(m.MinRTTSyn)),
		RttAvg: proto.Uint64(uint64(m.MinRTTAvg)),
		ArtAvg: proto.Uint64(uint64(m.MinARTAvg)),
	}
}

func pbToPerfMeterMin(m *pb.RttStats, meter *PerfMeterMin) {
	meter.MinRTTSyn = time.Duration(m.GetRttSyn())
	meter.MinRTTAvg = time.Duration(m.GetRttAvg())
	meter.MinARTAvg = time.Duration(m.GetArtAvg())
}

func GeoMeterToPB(m *GeoMeter) *pb.GeoMeter {
	return &pb.GeoMeter{
		SumClosedFlowCount:      proto.Uint64(m.SumClosedFlowCount),
		SumAbnormalFlowCount:    proto.Uint64(m.SumAbnormalFlowCount),
		SumClosedFlowDurationUs: proto.Uint64(m.SumClosedFlowDuration * 1000), // us
		SumPacketTx:             proto.Uint64(m.SumPacketTx),
		SumPacketRx:             proto.Uint64(m.SumPacketRx),
		SumBitTx:                proto.Uint64(m.SumBitTx),
		SumBitRx:                proto.Uint64(m.SumBitRx),
		SumRttSynClient:         proto.Uint64(uint64(m.SumRTTSynClient)),
		SumRttSynClientFlow:     proto.Uint64(m.SumRTTSynClientFlow),
	}
}

func PBToGeoMeter(m *pb.GeoMeter, meter *GeoMeter) {
	if meter == nil {
		panic("meter为空")
	}

	meter.SumClosedFlowCount = m.GetSumClosedFlowCount()
	meter.SumAbnormalFlowCount = m.GetSumAbnormalFlowCount()
	meter.SumClosedFlowDuration = m.GetSumClosedFlowDurationUs() / 1000 // ms
	meter.SumPacketTx = m.GetSumPacketTx()
	meter.SumPacketRx = m.GetSumPacketRx()
	meter.SumBitTx = m.GetSumBitTx()
	meter.SumBitRx = m.GetSumBitRx()
	meter.SumRTTSynClient = time.Duration(m.GetSumRttSynClient())
	meter.SumRTTSynClientFlow = m.GetSumRttSynClientFlow()
}

func FPSMeterToPB(m *FPSMeter) *pb.FpsMeter {
	return &pb.FpsMeter{
		SumFlowCount:       proto.Uint64(m.SumFlowCount),
		SumNewFlowCount:    proto.Uint64(m.SumNewFlowCount),
		SumClosedFlowCount: proto.Uint64(m.SumClosedFlowCount),

		MaxFlowCount:    proto.Uint64(m.MaxFlowCount),
		MaxNewFlowCount: proto.Uint64(m.MaxNewFlowCount),
	}
}

func PBToFPSMeter(m *pb.FpsMeter, meter *FPSMeter) {
	if meter == nil {
		panic("meter为空")
	}

	meter.SumFlowCount = m.GetSumFlowCount()
	meter.SumNewFlowCount = m.GetSumNewFlowCount()
	meter.SumClosedFlowCount = m.GetSumClosedFlowCount()

	meter.MaxFlowCount = m.GetMaxFlowCount()
	meter.MaxNewFlowCount = m.GetMaxNewFlowCount()
}

func FlowMeterToPB(m *FlowMeter) *pb.FlowMeter {
	return &pb.FlowMeter{
		SumFlowCount:       proto.Uint64(m.SumFlowCount),
		SumNewFlowCount:    proto.Uint64(m.SumNewFlowCount),
		SumClosedFlowCount: proto.Uint64(m.SumClosedFlowCount),
		SumPacketTx:        proto.Uint64(m.SumPacketTx),
		SumPacketRx:        proto.Uint64(m.SumPacketRx),
		SumPacket:          proto.Uint64(m.SumPacketTx + m.SumPacketRx),
		SumBitTx:           proto.Uint64(m.SumBitTx),
		SumBitRx:           proto.Uint64(m.SumBitRx),
		SumBit:             proto.Uint64(m.SumBitTx + m.SumBitRx),
	}
}

func PBToFlowMeter(m *pb.FlowMeter, meter *FlowMeter) {
	if meter == nil {
		panic("meter为空")
	}

	meter.SumFlowCount = m.GetSumFlowCount()
	meter.SumNewFlowCount = m.GetSumNewFlowCount()
	meter.SumClosedFlowCount = m.GetSumClosedFlowCount()
	meter.SumPacketTx = m.GetSumPacketTx()
	meter.SumPacketRx = m.GetSumPacketRx()
	meter.SumBitTx = m.GetSumBitTx()
	meter.SumBitRx = m.GetSumBitRx()
}

func ConsoleLogMeterToPB(m *ConsoleLogMeter) *pb.ConsoleLogMeter {
	return &pb.ConsoleLogMeter{
		SumPacketTx:             proto.Uint64(m.SumPacketTx),
		SumPacketRx:             proto.Uint64(m.SumPacketRx),
		SumClosedFlowCount:      proto.Uint64(m.SumClosedFlowCount),
		SumClosedFlowDurationUs: proto.Uint64(m.SumClosedFlowDuration * 1000), // us
	}
}

func PBToConsoleLogMeter(m *pb.ConsoleLogMeter, meter *ConsoleLogMeter) {
	if meter == nil {
		panic("meter为空")
	}

	meter.SumPacketTx = m.GetSumPacketTx()
	meter.SumPacketRx = m.GetSumPacketRx()
	meter.SumClosedFlowCount = m.GetSumClosedFlowCount()
	meter.SumClosedFlowDuration = m.GetSumClosedFlowDurationUs() / 1000 // ms
}

func TypeMeterToPB(m *TypeMeter) *pb.TypeMeter {
	return &pb.TypeMeter{
		SumCountL_0S1S:  proto.Uint64(m.SumCountL0S1S),
		SumCountL_1S5S:  proto.Uint64(m.SumCountL1S5S),
		SumCountL_5S10S: proto.Uint64(m.SumCountL5S10S),
		SumCountL_10S1M: proto.Uint64(m.SumCountL10S1M),
		SumCountL_1M1H:  proto.Uint64(m.SumCountL1M1H),
		SumCountL_1H:    proto.Uint64(m.SumCountL1H),

		SumCountE_0K10K:   proto.Uint64(m.SumCountE0K10K),
		SumCountE_10K100K: proto.Uint64(m.SumCountE10K100K),
		SumCountE_100K1M:  proto.Uint64(m.SumCountE100K1M),
		SumCountE_1M100M:  proto.Uint64(m.SumCountE1M100M),
		SumCountE_100M1G:  proto.Uint64(m.SumCountE100M1G),
		SumCountE_1G:      proto.Uint64(m.SumCountE1G),

		SumCountTCRst:       proto.Uint64(m.SumCountTClientRst),
		SumCountTCHalfOpen:  proto.Uint64(m.SumCountTClientHalfOpen),
		SumCountTCHalfClose: proto.Uint64(m.SumCountTClientHalfClose),
		SumCountTSRst:       proto.Uint64(m.SumCountTServerRst),
		SumCountTSHalfOpen:  proto.Uint64(m.SumCountTServerHalfOpen),
		SumCountTSHalfClose: proto.Uint64(m.SumCountTServerHalfClose),
	}
}

func PBToTypeMeter(m *pb.TypeMeter, meter *TypeMeter) {
	if meter == nil {
		panic("meter为空")
	}

	meter.SumCountL0S1S = m.GetSumCountL_0S1S()
	meter.SumCountL1S5S = m.GetSumCountL_1S5S()
	meter.SumCountL5S10S = m.GetSumCountL_5S10S()
	meter.SumCountL10S1M = m.GetSumCountL_10S1M()
	meter.SumCountL1M1H = m.GetSumCountL_1M1H()
	meter.SumCountL1H = m.GetSumCountL_1H()

	meter.SumCountE0K10K = m.GetSumCountE_0K10K()
	meter.SumCountE10K100K = m.GetSumCountE_10K100K()
	meter.SumCountE100K1M = m.GetSumCountE_100K1M()
	meter.SumCountE1M100M = m.GetSumCountE_1M100M()
	meter.SumCountE100M1G = m.GetSumCountE_100M1G()
	meter.SumCountE1G = m.GetSumCountE_1G()

	meter.SumCountTClientRst = m.GetSumCountTCRst()
	meter.SumCountTClientHalfOpen = m.GetSumCountTCHalfOpen()
	meter.SumCountTClientHalfClose = m.GetSumCountTCHalfClose()
	meter.SumCountTServerRst = m.GetSumCountTSRst()
	meter.SumCountTServerHalfOpen = m.GetSumCountTSHalfOpen()
	meter.SumCountTServerHalfClose = m.GetSumCountTSHalfClose()
}
