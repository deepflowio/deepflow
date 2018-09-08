package datatype

import (
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket/layers"

	pb "gitlab.x.lan/yunshan/message/dfi"
)

const TYPE_MULTI = 100000000

func MarshalFlow(f *TaggedFlow) ([]byte, error) {
	aclIDs, policyIDs := getACLIDsAndPolicyIDs(f)
	flow := &pb.Flow{
		Exporter:   proto.Uint32(f.Exporter),
		CloseType:  proto.Uint32(uint32(f.CloseType)),
		FlowId:     proto.Uint64(f.FlowID),
		StartTime:  proto.Uint32(uint32(f.StartTime.Seconds())),
		EndTime:    proto.Uint32(uint32(f.EndTime.Seconds())),
		Duration:   proto.Uint64(uint64(f.Duration / time.Microsecond)),
		TimeBitmap: proto.Uint64(f.TimeBitmap),
		// L1
		InPort_0: proto.Uint32(f.InPort),
		// L2
		Vlan:    proto.Uint32(uint32(f.VLAN)),
		EthType: proto.Uint32(uint32(f.EthType)),
		MacSrc:  proto.Uint64(f.MACSrc),
		MacDst:  proto.Uint64(f.MACDst),
		// L3
		IpSrc: proto.Uint32(f.IPSrc),
		IpDst: proto.Uint32(f.IPDst),
		// L4
		Proto:      proto.Uint32(uint32(f.Proto)),
		PortSrc:    proto.Uint32(uint32(f.PortSrc)),
		PortDst:    proto.Uint32(uint32(f.PortDst)),
		TcpFlags_0: proto.Uint32(uint32(f.FlowMetricsPeerSrc.TCPFlags)),
		TcpFlags_1: proto.Uint32(uint32(f.FlowMetricsPeerDst.TCPFlags)),
		// Tunnel
		TunId:    proto.Uint64(uint64(f.TunnelInfo.Id)),
		TunIpSrc: proto.Uint32(f.TunnelInfo.Src),
		TunIpDst: proto.Uint32(f.TunnelInfo.Dst),
		TunType:  proto.Uint64(uint64(f.TunnelInfo.Type)),
		// Packet Counters
		ByteCnt_0:      proto.Uint64(f.FlowMetricsPeerSrc.ByteCount),
		ByteCnt_1:      proto.Uint64(f.FlowMetricsPeerDst.ByteCount),
		PktCnt_0:       proto.Uint64(f.FlowMetricsPeerSrc.PacketCount),
		PktCnt_1:       proto.Uint64(f.FlowMetricsPeerDst.PacketCount),
		TotalByteCnt_0: proto.Uint64(f.FlowMetricsPeerSrc.TotalByteCount),
		TotalByteCnt_1: proto.Uint64(f.FlowMetricsPeerDst.TotalByteCount),
		TotalPktCnt_0:  proto.Uint64(f.FlowMetricsPeerSrc.TotalPacketCount),
		TotalPktCnt_1:  proto.Uint64(f.FlowMetricsPeerDst.TotalPacketCount),
		// Platform Data
		SubnetId_0:         proto.Uint32(f.FlowMetricsPeerSrc.SubnetID),
		SubnetId_1:         proto.Uint32(f.FlowMetricsPeerDst.SubnetID),
		L3DeviceType_0:     proto.Uint32(uint32(f.FlowMetricsPeerSrc.L3DeviceType)),
		L3DeviceType_1:     proto.Uint32(uint32(f.FlowMetricsPeerDst.L3DeviceType)),
		L3DeviceId_0:       proto.Uint32(f.FlowMetricsPeerSrc.L3DeviceID),
		L3DeviceId_1:       proto.Uint32(f.FlowMetricsPeerDst.L3DeviceID),
		L3EpcId_0:          proto.Uint32(uint32(f.FlowMetricsPeerSrc.L3EpcID)),
		L3EpcId_1:          proto.Uint32(uint32(f.FlowMetricsPeerDst.L3EpcID)),
		Host_0:             proto.Uint32(f.FlowMetricsPeerSrc.Host),
		Host_1:             proto.Uint32(f.FlowMetricsPeerDst.Host),
		EpcId_0:            proto.Uint32(uint32(f.FlowMetricsPeerSrc.EpcID)),
		EpcId_1:            proto.Uint32(uint32(f.FlowMetricsPeerDst.EpcID)),
		DeviceType_0:       proto.Uint32(uint32(f.FlowMetricsPeerSrc.DeviceType)),
		DeviceType_1:       proto.Uint32(uint32(f.FlowMetricsPeerDst.DeviceType)),
		DeviceId_0:         proto.Uint32(f.FlowMetricsPeerSrc.DeviceID),
		DeviceId_1:         proto.Uint32(f.FlowMetricsPeerDst.DeviceID),
		IfType_0:           proto.Uint32(f.FlowMetricsPeerSrc.IfType),
		IfType_1:           proto.Uint32(f.FlowMetricsPeerDst.IfType),
		IsL2End_0:          proto.Bool(f.FlowMetricsPeerSrc.IsL2End),
		IsL2End_1:          proto.Bool(f.FlowMetricsPeerDst.IsL2End),
		IsL3End_0:          proto.Bool(f.FlowMetricsPeerSrc.IsL3End),
		IsL3End_1:          proto.Bool(f.FlowMetricsPeerDst.IsL3End),
		GroupIds_0:         f.GroupIDs0,
		GroupIds_1:         f.GroupIDs1,
		WhitelistRuleIds_0: f.WhitelistRuleIDs0,
		WhitelistRuleIds_1: f.WhitelistRuleIDs1,
		CustomTagIds_0:     f.CustomTagIDs0,
		CustomTagIds_1:     f.CustomTagIDs1,
		AclId:              aclIDs,
		PolicyId:           policyIDs,
	}
	// TCP Perf Data
	if f.Proto == layers.IPProtocolTCP {
		flow.RttSyn = proto.Uint64(uint64(f.RTTSyn))
		flow.Rtt = proto.Uint64(uint64(f.RTT))
		flow.SynRetransCnt_0 = proto.Uint64(uint64(f.TcpPerfCountsPeerSrc.SynRetransCount))
		flow.SynRetransCnt_1 = proto.Uint64(uint64(f.TcpPerfCountsPeerDst.SynRetransCount))
		flow.RetransCnt_0 = proto.Uint64(uint64(f.TcpPerfCountsPeerSrc.RetransCount))
		flow.RetransCnt_1 = proto.Uint64(uint64(f.TcpPerfCountsPeerDst.RetransCount))
		flow.ZeroWndCnt_0 = proto.Uint64(uint64(f.TcpPerfCountsPeerSrc.ZeroWinCount))
		flow.ZeroWndCnt_1 = proto.Uint64(uint64(f.TcpPerfCountsPeerDst.ZeroWinCount))
		flow.TotalRetransCnt = proto.Uint64(uint64(f.TotalRetransCount))
		flow.PshUrgCnt_0 = proto.Uint64(uint64(f.TcpPerfCountsPeerSrc.PshUrgCount))
		flow.PshUrgCnt_1 = proto.Uint64(uint64(f.TcpPerfCountsPeerSrc.PshUrgCount))
		flow.ArtAvg = proto.Uint64(uint64(f.ART))
		flow.AvgPktInterval = proto.Uint64(f.PacketIntervalAvg)
		flow.PktIntervalVariance = proto.Uint64(f.PacketIntervalVariance)
		flow.PktSizeVariance = proto.Uint64(f.PacketSizeVariance)
	}

	b, err := proto.Marshal(flow)
	if err != nil {
		return make([]byte, 0), err
	}
	return b, nil
}

func getACLIDsAndPolicyIDs(f *TaggedFlow) ([]uint32, []uint32) {
	acl := make(map[uint32]bool)
	policy := make(map[uint32]bool)
	for _, aclAction := range f.PolicyData.AclActions {
		acl[aclAction.AclId] = true
		for _, policyInfo := range aclAction.Policy {
			policy[uint32(policyInfo.Type)*TYPE_MULTI+policyInfo.Id] = true
		}
	}
	aclIDs := make([]uint32, 0, len(acl))
	for id := range acl {
		aclIDs = append(aclIDs, id)
	}
	policyIDs := make([]uint32, 0, len(policy))
	for id := range policy {
		policyIDs = append(policyIDs, id)
	}
	return aclIDs, policyIDs
}
