package flowgenerator

import (
	"github.com/google/gopacket/layers"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (m *FlowMap) initUdpFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	m.initFlow(flowExtra, meta)
	flowExtra.flowState = FLOW_STATE_ESTABLISHED
	flowExtra.timeout = openingTimeout
	m.updateUDPDirection(meta, flowExtra, true) // 新建流时更新ServiceTable并矫正流方向
	meta.IsActiveService = flowExtra.taggedFlow.IsActiveService
}

func (m *FlowMap) updateUdpFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	m.updateFlow(flowExtra, meta)
	if flowExtra.taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC].PacketCount > 0 &&
		flowExtra.taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST].PacketCount > 0 {
		flowExtra.timeout = establishedRstTimeout
	}
	meta.IsActiveService = flowExtra.taggedFlow.IsActiveService
}

func (m *FlowMap) updateUDPDirection(meta *MetaPacket, flowExtra *FlowExtra, isFirstPacket bool) {
	srcScore, dstScore := uint8(0), uint8(0)
	if meta.EthType == layers.EthernetTypeIPv4 {
		srcKey := ServiceKey(int16(meta.EndpointData.SrcInfo.L3EpcId), meta.IpSrc, meta.PortSrc)
		dstKey := ServiceKey(int16(meta.EndpointData.DstInfo.L3EpcId), meta.IpDst, meta.PortDst)

		srcScore, dstScore = m.udpServiceTable.GetUDPScore(isFirstPacket, srcKey, dstKey)
	} else {
		ServiceKey6(m.srcServiceKey, int16(meta.EndpointData.SrcInfo.L3EpcId), meta.Ip6Src, meta.PortSrc)
		ServiceKey6(m.dstServiceKey, int16(meta.EndpointData.DstInfo.L3EpcId), meta.Ip6Dst, meta.PortDst)

		srcScore, dstScore = m.udpServiceTable6.GetUDPScore(isFirstPacket, m.srcServiceKey, m.dstServiceKey)
	}
	if meta.Direction == SERVER_TO_CLIENT {
		srcScore, dstScore = dstScore, srcScore
	}
	if !IsClientToServer(srcScore, dstScore) {
		srcScore, dstScore = dstScore, srcScore
		reverseFlow(flowExtra)
		meta.Direction = OppositePacketDirection(meta.Direction)
	}
	flowExtra.taggedFlow.IsActiveService = IsActiveService(srcScore, dstScore)
}
