package flowgenerator

import (
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (m *FlowGenerator) getNonIpQuinTupleHash(meta *MetaPacket) uint64 {
	return meta.MacSrc ^ meta.MacDst
}

func (e *FlowExtra) keyMatchForNonIp(meta *MetaPacket) bool { // FIXME: 移动位置
	if true { // FIXME: 删除
		taggedFlow := e.taggedFlow
		flowMacSrc, flowMacDst := taggedFlow.MACSrc, taggedFlow.MACDst
		if flowMacSrc == meta.MacSrc && flowMacDst == meta.MacDst {
			meta.Direction = CLIENT_TO_SERVER
			return true
		}
		if flowMacSrc == meta.MacDst && flowMacDst == meta.MacSrc {
			meta.Direction = SERVER_TO_CLIENT
			return true
		}
	}
	return false
}

func (m *FlowMap) initNonIpFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	now := meta.Timestamp
	m.initFlow(flowExtra, meta, now)
	taggedFlow := flowExtra.taggedFlow
	taggedFlow.FlowMetricsPeerSrc.ArrTime0 = now
	taggedFlow.FlowMetricsPeerSrc.ArrTimeLast = now
	taggedFlow.FlowMetricsPeerSrc.TotalPacketCount = 1
	taggedFlow.FlowMetricsPeerSrc.PacketCount = 1
	taggedFlow.FlowMetricsPeerSrc.TickPacketCount = 1
	taggedFlow.FlowMetricsPeerSrc.TotalByteCount = uint64(meta.PacketLen)
	taggedFlow.FlowMetricsPeerSrc.ByteCount = uint64(meta.PacketLen)
	taggedFlow.FlowMetricsPeerSrc.TickByteCount = uint64(meta.PacketLen)
	updatePlatformData(taggedFlow, meta.EndpointData, false)
	m.fillGeoInfo(taggedFlow)
	flowExtra.flowState = FLOW_STATE_ESTABLISHED
	flowExtra.timeout = openingTimeout
}

func (m *FlowMap) updateNonIpFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	m.updateFlow(flowExtra, meta)
	if flowExtra.taggedFlow.FlowMetricsPeerSrc.PacketCount > 0 && flowExtra.taggedFlow.FlowMetricsPeerDst.PacketCount > 0 {
		flowExtra.timeout = establishedRstTimeout
	}
}
