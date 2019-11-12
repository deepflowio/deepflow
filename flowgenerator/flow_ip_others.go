package flowgenerator

import (
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (m *FlowMap) initIpOthersFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	m.initFlow(flowExtra, meta)
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
