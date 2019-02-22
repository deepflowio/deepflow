package protobuf

import (
	"time"

	"github.com/golang/protobuf/proto"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	pb "gitlab.x.lan/yunshan/message/dfi"
)

const TYPE_MULTI = 100000000

func MarshalFlow(f *datatype.TaggedFlow, bytes *utils.ByteBuffer) error {
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
		SubnetId_0:     proto.Uint32(f.FlowMetricsPeerSrc.SubnetID),
		SubnetId_1:     proto.Uint32(f.FlowMetricsPeerDst.SubnetID),
		L3DeviceType_0: proto.Uint32(uint32(f.FlowMetricsPeerSrc.L3DeviceType)),
		L3DeviceType_1: proto.Uint32(uint32(f.FlowMetricsPeerDst.L3DeviceType)),
		L3DeviceId_0:   proto.Uint32(f.FlowMetricsPeerSrc.L3DeviceID),
		L3DeviceId_1:   proto.Uint32(f.FlowMetricsPeerDst.L3DeviceID),
		L3EpcId_0:      proto.Uint32(uint32(f.FlowMetricsPeerSrc.L3EpcID)),
		L3EpcId_1:      proto.Uint32(uint32(f.FlowMetricsPeerDst.L3EpcID)),
		Host_0:         proto.Uint32(f.FlowMetricsPeerSrc.Host),
		Host_1:         proto.Uint32(f.FlowMetricsPeerDst.Host),
		EpcId_0:        proto.Uint32(uint32(f.FlowMetricsPeerSrc.EpcID)),
		EpcId_1:        proto.Uint32(uint32(f.FlowMetricsPeerDst.EpcID)),
		DeviceType_0:   proto.Uint32(uint32(f.FlowMetricsPeerSrc.DeviceType)),
		DeviceType_1:   proto.Uint32(uint32(f.FlowMetricsPeerDst.DeviceType)),
		DeviceId_0:     proto.Uint32(f.FlowMetricsPeerSrc.DeviceID),
		DeviceId_1:     proto.Uint32(f.FlowMetricsPeerDst.DeviceID),
		IfType_0:       proto.Uint32(f.FlowMetricsPeerSrc.IfType),
		IfType_1:       proto.Uint32(f.FlowMetricsPeerDst.IfType),
		IsL2End_0:      proto.Bool(f.FlowMetricsPeerSrc.IsL2End),
		IsL2End_1:      proto.Bool(f.FlowMetricsPeerDst.IsL2End),
		IsL3End_0:      proto.Bool(f.FlowMetricsPeerSrc.IsL3End),
		IsL3End_1:      proto.Bool(f.FlowMetricsPeerDst.IsL3End),
		GroupIds_0:     f.GroupIDs0,
		GroupIds_1:     f.GroupIDs1,
		AclId:          proto.Uint32(uint32(f.PolicyData.ACLID)),
		AclGids:        getACLGIDs(f),
		// Geo Info
		Country: proto.Uint32(uint32(f.Country)),
		Region:  proto.Uint32(uint32(f.Region)),
		Isp:     proto.Uint32(uint32(f.ISP)),
	}
	// TCP Perf Data
	if f.TcpPerfStats != nil {
		flow.RttSyn = proto.Uint64(uint64(f.RTTSyn))
		flow.RttSynClient = proto.Uint64(uint64(f.RTTSynClient))
		flow.RttSynServer = proto.Uint64(uint64(f.RTTSynServer))
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

	buf := bytes.Use(flow.Size())
	if _, err := flow.MarshalTo(buf); err != nil {
		return err
	}
	return nil
}

func getACLGIDs(f *datatype.TaggedFlow) []uint32 {
	set := make(map[datatype.ACLID]bool)
	for _, aclAction := range f.PolicyData.AclActions {
		g := aclAction.GetACLGID()
		if g > 0 {
			set[g] = true
		}
	}
	aclGIDs := make([]uint32, 0, len(set))
	for id := range set {
		aclGIDs = append(aclGIDs, uint32(id))
	}
	return aclGIDs
}
