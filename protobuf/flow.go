package protobuf

import (
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	pb "gitlab.x.lan/yunshan/message/dfi"
)

const TYPE_MULTI = 100000000

func MarshalFlow(f *datatype.TaggedFlow, bytes *utils.ByteBuffer) error {
	flowMetricsPeerSrc := &f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST]

	flow := &pb.Flow{
		VtapId:     proto.Uint32(uint32(f.VtapId)),
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
		TcpFlags_0: proto.Uint32(uint32(flowMetricsPeerSrc.TCPFlags)),
		TcpFlags_1: proto.Uint32(uint32(flowMetricsPeerDst.TCPFlags)),
		// Tunnel
		TunId:    proto.Uint64(uint64(f.TunnelInfo.Id)),
		TunIpSrc: proto.Uint32(f.TunnelInfo.Src),
		TunIpDst: proto.Uint32(f.TunnelInfo.Dst),
		TunType:  proto.Uint64(uint64(f.TunnelInfo.Type)),
		// Packet Counters
		ByteCnt_0:      proto.Uint64(flowMetricsPeerSrc.ByteCount),
		ByteCnt_1:      proto.Uint64(flowMetricsPeerDst.ByteCount),
		PktCnt_0:       proto.Uint64(flowMetricsPeerSrc.PacketCount),
		PktCnt_1:       proto.Uint64(flowMetricsPeerDst.PacketCount),
		TotalByteCnt_0: proto.Uint64(flowMetricsPeerSrc.TotalByteCount),
		TotalByteCnt_1: proto.Uint64(flowMetricsPeerDst.TotalByteCount),
		TotalPktCnt_0:  proto.Uint64(flowMetricsPeerSrc.TotalPacketCount),
		TotalPktCnt_1:  proto.Uint64(flowMetricsPeerDst.TotalPacketCount),
		// Platform Data
		SubnetId_0:     proto.Uint32(flowMetricsPeerSrc.SubnetID),
		SubnetId_1:     proto.Uint32(flowMetricsPeerDst.SubnetID),
		L3DeviceType_0: proto.Uint32(uint32(flowMetricsPeerSrc.L3DeviceType)),
		L3DeviceType_1: proto.Uint32(uint32(flowMetricsPeerDst.L3DeviceType)),
		L3DeviceId_0:   proto.Uint32(flowMetricsPeerSrc.L3DeviceID),
		L3DeviceId_1:   proto.Uint32(flowMetricsPeerDst.L3DeviceID),
		L3EpcId_0:      proto.Uint32(uint32(flowMetricsPeerSrc.L3EpcID)),
		L3EpcId_1:      proto.Uint32(uint32(flowMetricsPeerDst.L3EpcID)),
		Host_0:         proto.Uint32(flowMetricsPeerSrc.Host),
		Host_1:         proto.Uint32(flowMetricsPeerDst.Host),
		EpcId_0:        proto.Uint32(uint32(flowMetricsPeerSrc.EpcID)),
		EpcId_1:        proto.Uint32(uint32(flowMetricsPeerDst.EpcID)),
		DeviceType_0:   proto.Uint32(uint32(flowMetricsPeerSrc.DeviceType)),
		DeviceType_1:   proto.Uint32(uint32(flowMetricsPeerDst.DeviceType)),
		DeviceId_0:     proto.Uint32(flowMetricsPeerSrc.DeviceID),
		DeviceId_1:     proto.Uint32(flowMetricsPeerDst.DeviceID),
		IsL2End_0:      proto.Bool(flowMetricsPeerSrc.IsL2End),
		IsL2End_1:      proto.Bool(flowMetricsPeerDst.IsL2End),
		IsL3End_0:      proto.Bool(flowMetricsPeerSrc.IsL3End),
		IsL3End_1:      proto.Bool(flowMetricsPeerDst.IsL3End),
		GroupIds_0:     f.GroupIDs0,
		GroupIds_1:     f.GroupIDs1,
		AclId:          proto.Uint32(uint32(f.PolicyData.ACLID)),
		AclGids:        getACLGIDs(f),
		// Geo Info
		Country: proto.Uint32(uint32(f.Country)),
		Region:  proto.Uint32(uint32(f.Region)),
		Isp:     proto.Uint32(uint32(f.ISP)),
		GeoEnd:  proto.Uint32(uint32(f.GeoEnd)),
	}

	if f.EthType == layers.EthernetTypeIPv6 {
		flow.Ip6Src = append(flow.Ip6Src, f.IP6Src...)
		flow.Ip6Dst = append(flow.Ip6Dst, f.IP6Dst...)
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
