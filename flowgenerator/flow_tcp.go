package flowgenerator

import (
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (m *FlowMap) initTcpFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	now := meta.Timestamp
	m.initFlow(flowExtra, meta, now)
	taggedFlow := flowExtra.taggedFlow
	flags := uint8(0)
	if meta.TcpData != nil {
		flags = meta.TcpData.Flags
	}
	taggedFlow.FlowMetricsPeerSrc.TCPFlags |= flags
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

	m.updateTCPDirection(meta, flowExtra, true)
	flowExtra.setMetaPacketActiveService(meta)

	flags = flags & TCP_FLAG_MASK
	if m.StatePreprocess(meta, flags) || meta.Invalid {
		flowExtra.timeout = exceptionTimeout
		flowExtra.flowState = FLOW_STATE_EXCEPTION
	}

	m.updateFlowStateMachine(flowExtra, flags, meta.Direction == SERVER_TO_CLIENT)
}

func (m *FlowMap) updateTcpFlow(flowExtra *FlowExtra, meta *MetaPacket) bool { // return: closed
	taggedFlow := flowExtra.taggedFlow
	flags := uint8(0)
	if meta.TcpData != nil {
		flags = meta.TcpData.Flags
	}
	if meta.Direction == SERVER_TO_CLIENT {
		taggedFlow.FlowMetricsPeerDst.TCPFlags |= flags
	} else {
		taggedFlow.FlowMetricsPeerSrc.TCPFlags |= flags
	}
	m.updateFlow(flowExtra, meta)

	m.updateTCPDirection(meta, flowExtra, false)
	flowExtra.setMetaPacketActiveService(meta)

	if m.StatePreprocess(meta, flags) || meta.Invalid {
		flowExtra.timeout = exceptionTimeout
		flowExtra.flowState = FLOW_STATE_EXCEPTION
		return false
	}
	return m.updateFlowStateMachine(flowExtra, flags, meta.Direction == SERVER_TO_CLIENT)
}

func (m *FlowMap) updateTCPDirection(meta *MetaPacket, flowExtra *FlowExtra, isFirstPacket bool) {
	srcKey := ServiceKey(int16(meta.EndpointData.SrcInfo.L3EpcId), meta.IpSrc, meta.PortSrc)
	dstKey := ServiceKey(int16(meta.EndpointData.DstInfo.L3EpcId), meta.IpDst, meta.PortDst)

	srcScore, dstScore := m.tcpServiceTable.GetTCPScore(isFirstPacket, meta.TcpData.Flags, srcKey, dstKey)
	if meta.Direction == SERVER_TO_CLIENT {
		srcScore, dstScore = dstScore, srcScore
	}
	if !IsClientToServer(srcScore, dstScore) {
		flowExtra.reverseFlow()
		flowExtra.reversed = !flowExtra.reversed
		meta.Direction = (CLIENT_TO_SERVER + SERVER_TO_CLIENT) - meta.Direction // reverse
	}
	flowExtra.taggedFlow.Flow.IsActiveService = IsActiveService(srcScore, dstScore)
}
