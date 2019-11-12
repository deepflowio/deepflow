package flowgenerator

import (
	"time"

	"github.com/google/gopacket/layers"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (m *FlowMap) initTcpFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	m.initFlow(flowExtra, meta)
	flags := meta.TcpData.Flags

	m.updateTCPDirection(meta, flags, flowExtra, true) // 新建流时更新ServiceTable并矫正流方向
	meta.IsActiveService = flowExtra.taggedFlow.IsActiveService

	if StatePreprocess(meta, flags) || meta.Invalid {
		flowExtra.timeout = exceptionTimeout
		flowExtra.flowState = FLOW_STATE_EXCEPTION
	}

	m.updateFlowStateMachine(flowExtra, flags, meta.Direction == SERVER_TO_CLIENT)
}

func (m *FlowMap) updateTcpFlow(flowExtra *FlowExtra, meta *MetaPacket) bool { // return: closed
	taggedFlow := flowExtra.taggedFlow
	flags := meta.TcpData.Flags
	taggedFlow.FlowMetricsPeers[meta.Direction].TCPFlags |= flags
	m.updateFlow(flowExtra, meta)

	if flags&TCP_SYN != 0 { // 有特殊包时更新ServiceTable并矫正流方向：SYN+ACK或SYN
		m.updateTCPDirection(meta, flags, flowExtra, false)
	}
	meta.IsActiveService = taggedFlow.IsActiveService

	if StatePreprocess(meta, flags) || meta.Invalid {
		flowExtra.timeout = exceptionTimeout
		flowExtra.flowState = FLOW_STATE_EXCEPTION
		return false
	}
	return m.updateFlowStateMachine(flowExtra, flags, meta.Direction == SERVER_TO_CLIENT)
}

func (m *FlowMap) updateFlowStateMachine(flowExtra *FlowExtra, flags uint8, serverToClient bool) bool {
	taggedFlow := flowExtra.taggedFlow
	var timeout time.Duration
	var flowState FlowState
	closed := false
	if stateValue := m.stateMachineMaster[flowExtra.flowState][flags&TCP_FLAG_MASK]; stateValue != nil {
		timeout = stateValue.timeout
		flowState = stateValue.flowState
		closed = stateValue.closed
	} else {
		timeout = exceptionTimeout
		flowState = FLOW_STATE_EXCEPTION
		closed = false
	}
	if serverToClient { // 若flags对应的包是 服务端->客户端 时，还需要走一下Slave状态机
		if stateValue := m.stateMachineSlave[flowExtra.flowState][flags&TCP_FLAG_MASK]; stateValue != nil {
			timeout = stateValue.timeout
			flowState = stateValue.flowState
			closed = stateValue.closed
		}
	}
	flowExtra.flowState = flowState
	if taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC].TotalPacketCount == 0 ||
		taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST].TotalPacketCount == 0 {
		flowExtra.timeout = singleDirectionTimeout
	} else {
		flowExtra.timeout = timeout
	}
	return closed
}

func (m *FlowMap) updateTCPDirection(meta *MetaPacket, flags uint8, flowExtra *FlowExtra, isFirstPacket bool) {
	srcScore, dstScore := uint8(0), uint8(0)
	if meta.EthType == layers.EthernetTypeIPv4 {
		srcKey := ServiceKey(int16(meta.EndpointData.SrcInfo.L3EpcId), meta.IpSrc, meta.PortSrc)
		dstKey := ServiceKey(int16(meta.EndpointData.DstInfo.L3EpcId), meta.IpDst, meta.PortDst)

		srcScore, dstScore = m.tcpServiceTable.GetTCPScore(isFirstPacket, flags, srcKey, dstKey)
	} else {
		ServiceKey6(m.srcServiceKey, int16(meta.EndpointData.SrcInfo.L3EpcId), meta.Ip6Src, meta.PortSrc)
		ServiceKey6(m.dstServiceKey, int16(meta.EndpointData.DstInfo.L3EpcId), meta.Ip6Dst, meta.PortDst)

		srcScore, dstScore = m.tcpServiceTable6.GetTCPScore(isFirstPacket, flags, m.srcServiceKey, m.dstServiceKey)
	}
	if meta.Direction == SERVER_TO_CLIENT {
		srcScore, dstScore = dstScore, srcScore
	}
	if !IsClientToServer(srcScore, dstScore) {
		srcScore, dstScore = dstScore, srcScore
		reverseFlow(flowExtra.taggedFlow)
		flowExtra.reversed = !flowExtra.reversed
		meta.Direction = (CLIENT_TO_SERVER + SERVER_TO_CLIENT) - meta.Direction // reverse
	}
	flowExtra.taggedFlow.IsActiveService = IsActiveService(srcScore, dstScore)
}
