package flowgenerator

import (
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (m *FlowMap) initIpOthersFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	m.initFlow(flowExtra, meta)
	taggedFlow := flowExtra.taggedFlow
	flowMetricsPeerSrc := &taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC]
	flowMetricsPeerSrc.TotalPacketCount = 1
	flowMetricsPeerSrc.PacketCount = 1
	flowMetricsPeerSrc.TickPacketCount = 1
	flowMetricsPeerSrc.TotalByteCount = uint64(meta.PacketLen)
	flowMetricsPeerSrc.ByteCount = uint64(meta.PacketLen)
	flowMetricsPeerSrc.TickByteCount = uint64(meta.PacketLen)
	updatePlatformData(taggedFlow, meta.EndpointData, false)
	m.fillGeoInfo(taggedFlow)
	flowExtra.flowState = FLOW_STATE_ESTABLISHED
	flowExtra.timeout = openingTimeout
}

func (m *FlowMap) updateIpOthersFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	m.updateFlow(flowExtra, meta)
	if flowExtra.taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC].PacketCount > 0 &&
		flowExtra.taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST].PacketCount > 0 {
		flowExtra.timeout = establishedRstTimeout
	}
}
