package zerodoc

import (
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	pb "gitlab.x.lan/yunshan/message/zero"
)

func TagToPB(t *Tag) *pb.Tag {
	tag := &pb.Tag{
		Code: proto.Uint64(uint64(t.Code)),
	}

	if t.Code&IP != 0 {
		tag.Ip = proto.Uint32(t.IP)
	}
	if t.Code&MAC != 0 {
		tag.Mac = proto.Uint64(t.MAC)
	}
	if t.Code&GroupID != 0 {
		tag.GroupId = proto.Uint32(uint32(t.GroupID))
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

	if t.Code&IPPath != 0 {
		tag.Ip_0 = proto.Uint32(t.IP0)
		tag.Ip_1 = proto.Uint32(t.IP1)
	}
	if t.Code&MACPath != 0 {
		tag.Mac_0 = proto.Uint64(t.MAC0)
		tag.Mac_1 = proto.Uint64(t.MAC1)
	}
	if t.Code&GroupIDPath != 0 {
		tag.GroupId_0 = proto.Uint32(uint32(t.GroupID0))
		tag.GroupId_1 = proto.Uint32(uint32(t.GroupID1))
	}
	if t.Code&L2EpcIDPath != 0 {
		tag.L2EpcId_0 = proto.Int32(int32(t.L2EpcID0))
		tag.L2EpcId_1 = proto.Int32(int32(t.L2EpcID1))
	}
	if t.Code&L3EpcIDPath != 0 {
		tag.L3EpcId_0 = proto.Int32(int32(t.L3EpcID0))
		tag.L3EpcId_1 = proto.Int32(int32(t.L3EpcID1))
	}
	if t.Code&L2DevicePath != 0 {
		tag.L2DeviceId_0 = proto.Uint32(uint32(t.L2DeviceID0))
		tag.L2DeviceType_0 = pb.DeviceType(t.L2DeviceType0).Enum()
		tag.L2DeviceId_1 = proto.Uint32(uint32(t.L2DeviceID1))
		tag.L2DeviceType_1 = pb.DeviceType(t.L2DeviceType1).Enum()
	}
	if t.Code&L3DevicePath != 0 {
		tag.L3DeviceId_0 = proto.Uint32(uint32(t.L3DeviceID0))
		tag.L3DeviceType_0 = pb.DeviceType(t.L3DeviceType0).Enum()
		tag.L3DeviceId_1 = proto.Uint32(uint32(t.L3DeviceID1))
		tag.L3DeviceType_1 = pb.DeviceType(t.L3DeviceType1).Enum()
	}

	if t.Code&Direction != 0 {
		tag.Direction = pb.Direction(t.Direction).Enum()
	}
	if t.Code&Policy != 0 {
		tag.PolicyType = proto.Uint32(uint32(t.PolicyType))
		tag.PolicyId = proto.Uint32(uint32(t.PolicyID))
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
	if t.Code&Host != 0 {
		tag.Host = proto.Uint32(t.Host)
	}
	if t.Code&VTAP != 0 {
		tag.Vtap = proto.Uint32(t.VTAP)
	}
	if t.Code&TAPType != 0 {
		tag.TapType = pb.TapType(t.TAPType).Enum()
	}
	if t.Code&SubnetID != 0 {
		tag.SubnetId = proto.Uint32(uint32(t.SubnetID))
	}
	if t.Code&ACLID != 0 {
		tag.AclId = proto.Uint32(uint32(t.ACLID))
	}

	if t.CustomFields != nil {
		n := 0
		fields := make([]pb.StringField, CustomFieldNumber)
		for i := 0; i < CustomFieldNumber; i++ {
			code := 1 << uint(i+64-CustomFieldNumber)
			if t.Code&Code(code) != 0 && t.CustomFields[i] != nil {
				fields[n] = pb.StringField{
					Key:   proto.String(t.CustomFields[i].Key),
					Value: proto.String(t.CustomFields[i].Value),
				}
				n++
			}
		}
		tag.CustomFields = make([]*pb.StringField, n)
		for i := 0; i < n; i++ {
			tag.CustomFields[i] = &fields[i]
		}
	}

	return tag
}

func PBToTag(t *pb.Tag) *Tag {
	tag := &Tag{
		Field: &Field{},
		Code:  Code(t.GetCode()),
	}

	if tag.Code&IP != 0 {
		tag.IP = t.GetIp()
	}
	if tag.Code&MAC != 0 {
		tag.MAC = t.GetMac()
	}
	if tag.Code&GroupID != 0 {
		tag.GroupID = int(t.GetGroupId())
	}
	if tag.Code&L2EpcID != 0 {
		tag.L2EpcID = int(t.GetL2EpcId())
	}
	if tag.Code&L3EpcID != 0 {
		tag.L3EpcID = int(t.GetL3EpcId())
	}
	if tag.Code&L2Device != 0 {
		tag.L2DeviceID = int(t.GetL2DeviceId())
		tag.L2DeviceType = DeviceType(t.GetL2DeviceType())
	}
	if tag.Code&L3Device != 0 {
		tag.L3DeviceID = int(t.GetL3DeviceId())
		tag.L3DeviceType = DeviceType(t.GetL3DeviceType())
	}

	if tag.Code&IPPath != 0 {
		tag.IP0 = t.GetIp_0()
		tag.IP1 = t.GetIp_1()
	}
	if tag.Code&MACPath != 0 {
		tag.MAC0 = t.GetMac_0()
		tag.MAC1 = t.GetMac_1()
	}
	if tag.Code&GroupIDPath != 0 {
		tag.GroupID0 = int(t.GetGroupId_0())
		tag.GroupID1 = int(t.GetGroupId_1())
	}
	if tag.Code&L2EpcIDPath != 0 {
		tag.L2EpcID0 = int(t.GetL2EpcId_0())
		tag.L2EpcID1 = int(t.GetL2EpcId_1())
	}
	if tag.Code&L3EpcIDPath != 0 {
		tag.L3EpcID0 = int(t.GetL3EpcId_0())
		tag.L3EpcID1 = int(t.GetL3EpcId_1())
	}
	if tag.Code&L2DevicePath != 0 {
		tag.L2DeviceID0 = int(t.GetL2DeviceId_0())
		tag.L2DeviceType0 = DeviceType(t.GetL2DeviceType_0())
		tag.L2DeviceID1 = int(t.GetL2DeviceId_1())
		tag.L2DeviceType1 = DeviceType(t.GetL2DeviceType_1())
	}
	if tag.Code&L3DevicePath != 0 {
		tag.L3DeviceID0 = int(t.GetL3DeviceId_0())
		tag.L3DeviceType0 = DeviceType(t.GetL3DeviceType_0())
		tag.L3DeviceID1 = int(t.GetL3DeviceId_1())
		tag.L3DeviceType1 = DeviceType(t.GetL3DeviceType_1())
	}

	if tag.Code&Direction != 0 {
		tag.Direction = DirectionEnum(t.GetDirection())
	}
	if tag.Code&Policy != 0 {
		tag.PolicyType = datatype.PolicyType(t.GetPolicyType())
		tag.PolicyID = int(t.GetPolicyId())
	}
	if tag.Code&VLANID != 0 {
		tag.VLANID = int(t.GetVlanId())
	}
	if tag.Code&Protocol != 0 {
		tag.Protocol = layers.IPProtocol(uint8(t.GetProtocol()))
	}
	if tag.Code&ServerPort != 0 {
		tag.ServerPort = int(t.GetServerPort())
	}
	if tag.Code&Host != 0 {
		tag.Host = t.GetHost()
	}
	if tag.Code&VTAP != 0 {
		tag.VTAP = t.GetVtap()
	}
	if tag.Code&TAPType != 0 {
		tag.TAPType = TAPTypeEnum(t.GetTapType())
	}
	if tag.Code&SubnetID != 0 {
		tag.SubnetID = int(t.GetSubnetId())
	}
	if tag.Code&ACLID != 0 {
		tag.ACLID = int(t.GetAclId())
	}

	if t.GetCustomFields() != nil && tag.Code&0xFFFF000000000000 != 0 {
		fields := t.GetCustomFields()
		tag.CustomFields = make([]*StringField, CustomFieldNumber)
		n := 0
		for i := 0; i < CustomFieldNumber; i++ {
			code := 1 << uint(i+64-CustomFieldNumber)
			if tag.Code&Code(code) != 0 {
				tag.CustomFields[i] = &StringField{fields[n].GetKey(), fields[n].GetValue()}
				n++
			}
		}
	}

	return tag
}

func UsageMeterToPB(m *UsageMeter) *pb.UsageMeter {
	return &pb.UsageMeter{
		Sum: &pb.UsageStats{
			PacketTx: proto.Uint64(m.SumPacketTx),
			PacketRx: proto.Uint64(m.SumPacketRx),
			Packet:   proto.Uint64(m.SumPacket),
			BitTx:    proto.Uint64(m.SumBitTx),
			BitRx:    proto.Uint64(m.SumBitRx),
			Bit:      proto.Uint64(m.SumBit),
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

func PBToUsageMeter(m *pb.UsageMeter) *UsageMeter {
	sum := m.GetSum()
	max := m.GetMax()
	return &UsageMeter{
		UsageMeterSum: UsageMeterSum{
			SumPacketTx: sum.GetPacketTx(),
			SumPacketRx: sum.GetPacketRx(),
			SumPacket:   sum.GetPacket(),
			SumBitTx:    sum.GetBitTx(),
			SumBitRx:    sum.GetBitRx(),
			SumBit:      sum.GetBit(),
		},
		UsageMeterMax: UsageMeterMax{
			MaxPacketTx: max.GetPacketTx(),
			MaxPacketRx: max.GetPacketRx(),
			MaxPacket:   max.GetPacket(),
			MaxBitTx:    max.GetBitTx(),
			MaxBitRx:    max.GetBitRx(),
			MaxBit:      max.GetBit(),
		},
	}
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

func PBToPerfMeter(m *pb.PerfMeter) *PerfMeter {
	return &PerfMeter{
		PerfMeterSum: *pbToPerfMeterSum(m.GetSum()),
		PerfMeterMax: *pbToPerfMeterMax(m.GetMax()),
		PerfMeterMin: *pbToPerfMeterMin(m.GetMin()),
	}
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

		RttSyn:        proto.Uint64(uint64(m.SumRTTSyn)),
		RttAvg:        proto.Uint64(uint64(m.SumRTTAvg)),
		RttSynFlow:    proto.Uint64(m.SumRTTSynFlow),
		RttAvgFlow:    proto.Uint64(m.SumRTTAvgFlow),
		RttSynPerFlow: proto.Uint64(m.SumRTTSynPerFlow),
		RttAvgPerFlow: proto.Uint64(m.SumRTTAvgPerFlow),

		ZeroWndCntTx: proto.Uint64(m.SumZeroWndCntTx),
		ZeroWndCntRx: proto.Uint64(m.SumZeroWndCntRx),
	}
}

func pbToPerfMeterSum(m *pb.PerfStats) *PerfMeterSum {
	return &PerfMeterSum{
		SumFlowCount:         m.GetFlowCount(),
		SumClosedFlowCount:   m.GetClosedFlowCount(),
		SumRetransFlowCount:  m.GetRetransFlowCount(),
		SumHalfOpenFlowCount: m.GetHalfOpenFlowCount(),
		SumPacketTx:          m.GetPacketTx(),
		SumPacketRx:          m.GetPacketRx(),
		SumRetransCntTx:      m.GetRetransCntTx(),
		SumRetransCntRx:      m.GetRetransCntRx(),

		SumRTTSyn:        time.Duration(m.GetRttSyn()),
		SumRTTAvg:        time.Duration(m.GetRttAvg()),
		SumRTTSynFlow:    m.GetRttSynFlow(),
		SumRTTAvgFlow:    m.GetRttAvgFlow(),
		SumRTTSynPerFlow: m.GetRttSynPerFlow(),
		SumRTTAvgPerFlow: m.GetRttAvgPerFlow(),

		SumZeroWndCntTx: m.GetZeroWndCntTx(),
		SumZeroWndCntRx: m.GetZeroWndCntRx(),
	}
}

func PerfMeterMaxToPB(m *PerfMeterMax) *pb.RttStats {
	return &pb.RttStats{
		RttSyn: proto.Uint64(uint64(m.MaxRTTSyn)),
		RttAvg: proto.Uint64(uint64(m.MaxRTTAvg)),
	}
}

func pbToPerfMeterMax(m *pb.RttStats) *PerfMeterMax {
	return &PerfMeterMax{
		MaxRTTSyn: time.Duration(m.GetRttSyn()),
		MaxRTTAvg: time.Duration(m.GetRttAvg()),
	}
}

func PerfMeterMinToPB(m *PerfMeterMin) *pb.RttStats {
	return &pb.RttStats{
		RttSyn: proto.Uint64(uint64(m.MinRTTSyn)),
		RttAvg: proto.Uint64(uint64(m.MinRTTAvg)),
	}
}

func pbToPerfMeterMin(m *pb.RttStats) *PerfMeterMin {
	return &PerfMeterMin{
		MinRTTSyn: time.Duration(m.GetRttSyn()),
		MinRTTAvg: time.Duration(m.GetRttAvg()),
	}
}

func GeoMeterToPB(m *GeoMeter) *pb.GeoMeter {
	return &pb.GeoMeter{
		SumClosedFlowCount:      proto.Uint64(m.SumClosedFlowCount),
		SumAbnormalFlowCount:    proto.Uint64(m.SumAbnormalFlowCount),
		SumClosedFlowDurationUs: proto.Uint64(uint64(m.SumClosedFlowDuration / time.Microsecond)),
		SumPacketTx:             proto.Uint64(m.SumPacketTx),
		SumPacketRx:             proto.Uint64(m.SumPacketRx),
		SumBitTx:                proto.Uint64(m.SumBitTx),
		SumBitRx:                proto.Uint64(m.SumBitRx),
		SumRttSyn:               proto.Uint64(uint64(m.SumRTTSyn)),
		SumRttSynFlow:           proto.Uint64(m.SumRTTSynFlow),
	}
}

func PBToGeoMeter(m *pb.GeoMeter) *GeoMeter {
	return &GeoMeter{
		SumClosedFlowCount:    m.GetSumClosedFlowCount(),
		SumAbnormalFlowCount:  m.GetSumAbnormalFlowCount(),
		SumClosedFlowDuration: time.Duration(m.GetSumClosedFlowDurationUs()) * time.Microsecond,
		SumPacketTx:           m.GetSumPacketTx(),
		SumPacketRx:           m.GetSumPacketRx(),
		SumBitTx:              m.GetSumBitTx(),
		SumBitRx:              m.GetSumBitRx(),
		SumRTTSyn:             time.Duration(m.GetSumRttSyn()),
		SumRTTSynFlow:         m.GetSumRttSynFlow(),
	}
}

func FlowMeterToPB(m *FlowMeter) *pb.FlowMeter {
	return &pb.FlowMeter{
		SumFlowCount:       proto.Uint64(m.SumFlowCount),
		SumNewFlowCount:    proto.Uint64(m.SumNewFlowCount),
		SumClosedFlowCount: proto.Uint64(m.SumClosedFlowCount),

		SumClosedFlowCountL_0S1S:  proto.Uint64(m.SumClosedFlowCountL0S1S),
		SumClosedFlowCountL_1S5S:  proto.Uint64(m.SumClosedFlowCountL1S5S),
		SumClosedFlowCountL_5S10S: proto.Uint64(m.SumClosedFlowCountL5S10S),
		SumClosedFlowCountL_10S1M: proto.Uint64(m.SumClosedFlowCountL10S1M),
		SumClosedFlowCountL_1M1H:  proto.Uint64(m.SumClosedFlowCountL1M1H),
		SumClosedFlowCountL_1H:    proto.Uint64(m.SumClosedFlowCountL1H),

		SumClosedFlowCountE_0K10K:   proto.Uint64(m.SumClosedFlowCountE0K10K),
		SumClosedFlowCountE_10K100K: proto.Uint64(m.SumClosedFlowCountE10K100K),
		SumClosedFlowCountE_100K1M:  proto.Uint64(m.SumClosedFlowCountE100K1M),
		SumClosedFlowCountE_1M100M:  proto.Uint64(m.SumClosedFlowCountE1M100M),
		SumClosedFlowCountE_100M1G:  proto.Uint64(m.SumClosedFlowCountE100M1G),
		SumClosedFlowCountE_1G:      proto.Uint64(m.SumClosedFlowCountE1G),

		SumClosedFlowCountTRst:       proto.Uint64(m.SumClosedFlowCountTRst),
		SumClosedFlowCountTHalfOpen:  proto.Uint64(m.SumClosedFlowCountTHalfOpen),
		SumClosedFlowCountTHalfClose: proto.Uint64(m.SumClosedFlowCountTHalfClose),

		MaxFlowCount:    proto.Uint64(m.MaxFlowCount),
		MaxNewFlowCount: proto.Uint64(m.MaxNewFlowCount),
	}
}

func PBToFlowMeter(m *pb.FlowMeter) *FlowMeter {
	return &FlowMeter{
		SumFlowCount:       m.GetSumFlowCount(),
		SumNewFlowCount:    m.GetSumNewFlowCount(),
		SumClosedFlowCount: m.GetSumClosedFlowCount(),

		SumClosedFlowCountL0S1S:  m.GetSumClosedFlowCountL_0S1S(),
		SumClosedFlowCountL1S5S:  m.GetSumClosedFlowCountL_1S5S(),
		SumClosedFlowCountL5S10S: m.GetSumClosedFlowCountL_5S10S(),
		SumClosedFlowCountL10S1M: m.GetSumClosedFlowCountL_10S1M(),
		SumClosedFlowCountL1M1H:  m.GetSumClosedFlowCountL_1M1H(),
		SumClosedFlowCountL1H:    m.GetSumClosedFlowCountL_1H(),

		SumClosedFlowCountE0K10K:   m.GetSumClosedFlowCountE_0K10K(),
		SumClosedFlowCountE10K100K: m.GetSumClosedFlowCountE_10K100K(),
		SumClosedFlowCountE100K1M:  m.GetSumClosedFlowCountE_100K1M(),
		SumClosedFlowCountE1M100M:  m.GetSumClosedFlowCountE_1M100M(),
		SumClosedFlowCountE100M1G:  m.GetSumClosedFlowCountE_100M1G(),
		SumClosedFlowCountE1G:      m.GetSumClosedFlowCountE_1G(),

		SumClosedFlowCountTRst:       m.GetSumClosedFlowCountTRst(),
		SumClosedFlowCountTHalfOpen:  m.GetSumClosedFlowCountTHalfOpen(),
		SumClosedFlowCountTHalfClose: m.GetSumClosedFlowCountTHalfClose(),

		MaxFlowCount:    m.GetMaxFlowCount(),
		MaxNewFlowCount: m.GetMaxNewFlowCount(),
	}
}

func PlatformMeterToPB(m *PlatformMeter) *pb.PlatformMeter {
	return &pb.PlatformMeter{
		SumClosedFlowCount: proto.Uint64(m.SumClosedFlowCount),
		SumPacket:          proto.Uint64(m.SumPacket),
		SumBit:             proto.Uint64(m.SumBit),
	}
}

func PBToPlatformMeter(m *pb.PlatformMeter) *PlatformMeter {
	return &PlatformMeter{
		SumClosedFlowCount: m.GetSumClosedFlowCount(),
		SumPacket:          m.GetSumPacket(),
		SumBit:             m.GetSumBit(),
	}
}

func ConsoleLogMeterToPB(m *ConsoleLogMeter) *pb.ConsoleLogMeter {
	return &pb.ConsoleLogMeter{
		SumPacketTx:             proto.Uint64(m.SumPacketTx),
		SumPacketRx:             proto.Uint64(m.SumPacketRx),
		SumClosedFlowCount:      proto.Uint64(m.SumClosedFlowCount),
		SumClosedFlowDurationUs: proto.Uint64(uint64(m.SumClosedFlowDuration / time.Microsecond)),
	}
}

func PBToConsoleLogMeter(m *pb.ConsoleLogMeter) *ConsoleLogMeter {
	return &ConsoleLogMeter{
		SumPacketTx:           m.GetSumPacketTx(),
		SumPacketRx:           m.GetSumPacketRx(),
		SumClosedFlowCount:    m.GetSumClosedFlowCount(),
		SumClosedFlowDuration: time.Duration(m.GetSumClosedFlowDurationUs()) * time.Microsecond,
	}
}

func IPDatabaseMeterToPB(m *IPDatabaseMeter) *pb.IpDatabaseMeter {
	return &pb.IpDatabaseMeter{
		SumBit:             proto.Uint64(m.SumBit),
		SumClosedFlowCount: proto.Uint64(m.SumClosedFlowCount),
	}
}

func PBToIPDatabaseMeter(m *pb.IpDatabaseMeter) *IPDatabaseMeter {
	return &IPDatabaseMeter{
		SumBit:             m.GetSumBit(),
		SumClosedFlowCount: m.GetSumClosedFlowCount(),
	}
}
