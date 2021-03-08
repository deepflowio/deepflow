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
		FlowSource: proto.Uint32(uint32(f.FlowSource)),
		StartTime:  proto.Uint32(uint32(f.StartTime.Seconds())),
		EndTime:    proto.Uint32(uint32(f.EndTime.Seconds())),
		Duration:   proto.Uint64(uint64(f.Duration / time.Microsecond)),
		// L1
		TapType: proto.Uint32(uint32(f.TapType)),
		TapPort: proto.Uint32(f.TapPort),
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
		TunTxId:   proto.Uint32(f.Tunnel.TxId),
		TunTxIp_0: proto.Uint32(f.Tunnel.TxIP0),
		TunTxIp_1: proto.Uint32(f.Tunnel.TxIP1),
		TunRxId:   proto.Uint32(f.Tunnel.RxId),
		TunRxIp_0: proto.Uint32(f.Tunnel.RxIP0),
		TunRxIp_1: proto.Uint32(f.Tunnel.RxIP1),
		TunType:   proto.Uint32(uint32(f.Tunnel.Type)),
		TunTier:   proto.Uint32(uint32(f.Tunnel.Tier)),
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
		L3EpcId_0: proto.Uint32(uint32(flowMetricsPeerSrc.L3EpcID)),
		L3EpcId_1: proto.Uint32(uint32(flowMetricsPeerDst.L3EpcID)),
		IsL2End_0: proto.Bool(flowMetricsPeerSrc.IsL2End),
		IsL2End_1: proto.Bool(flowMetricsPeerDst.IsL2End),
		IsL3End_0: proto.Bool(flowMetricsPeerSrc.IsL3End),
		IsL3End_1: proto.Bool(flowMetricsPeerDst.IsL3End),
		// Other
		CastTypeMap_0:   proto.Uint32(uint32(flowMetricsPeerSrc.CastTypeMap)),
		CastTypeMap_1:   proto.Uint32(uint32(flowMetricsPeerDst.CastTypeMap)),
		TcpFlagsMap_0:   proto.Uint32(uint32(flowMetricsPeerSrc.TCPFlagsMap)),
		TcpFlagsMap_1:   proto.Uint32(uint32(flowMetricsPeerDst.TCPFlagsMap)),
		TtlMap_0:        proto.Uint32(uint32(flowMetricsPeerSrc.TTLMap)),
		TtlMap_1:        proto.Uint32(uint32(flowMetricsPeerDst.TTLMap)),
		PacketSizeMap_0: proto.Uint32(uint32(flowMetricsPeerSrc.PacketSizeMap)),
		PacketSizeMap_1: proto.Uint32(uint32(flowMetricsPeerDst.PacketSizeMap)),
	}

	if f.EthType == layers.EthernetTypeIPv6 {
		flow.Ip6Src = append(flow.Ip6Src, f.IP6Src...)
		flow.Ip6Dst = append(flow.Ip6Dst, f.IP6Dst...)
	}

	// TCP Perf Data
	if f.FlowPerfStats != nil {
		flow.RttAvg = proto.Uint64(uint64(f.RTT))
		if f.RTTClientCount > 0 {
			flow.RttClientAvg = proto.Uint64(uint64(f.RTTClientSum / f.RTTClientCount))
		}
		if f.RTTServerCount > 0 {
			flow.RttServerAvg = proto.Uint64(uint64(f.RTTServerSum / f.RTTServerCount))
		}
		if f.SRTCount > 0 {
			flow.SrtAvg = proto.Uint64(uint64(f.SRTSum / f.SRTCount))
		}
		if f.ARTCount > 0 {
			flow.ArtAvg = proto.Uint64(uint64(f.ARTSum / f.ARTCount))
		}
		flow.RetransCnt_0 = proto.Uint64(uint64(f.TcpPerfCountsPeers[0].RetransCount))
		flow.RetransCnt_1 = proto.Uint64(uint64(f.TcpPerfCountsPeers[0].RetransCount))
		flow.ZeroWndCnt_0 = proto.Uint64(uint64(f.TcpPerfCountsPeers[1].ZeroWinCount))
		flow.ZeroWndCnt_1 = proto.Uint64(uint64(f.TcpPerfCountsPeers[1].ZeroWinCount))
		flow.TotalRetransCnt = proto.Uint64(uint64(f.TotalRetransCount))
	}

	buf := bytes.Use(flow.Size())
	if _, err := flow.MarshalTo(buf); err != nil {
		return err
	}
	return nil
}
