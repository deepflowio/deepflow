package flowgenerator

import (
	"sync/atomic"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (f *FlowGenerator) processTcpPacket(meta *MetaPacket) {
	hash := f.getQuinTupleHash(meta)
	flowCache := f.hashMap[hash%hashMapSize]
	flowCache.Lock()
	if flowExtra, element := f.keyMatch(flowCache, meta); flowExtra != nil {
		ok := false
		taggedFlow := flowExtra.taggedFlow
		if ok = f.updateTcpFlow(flowExtra, meta); ok {
			flowCache.flowList.Remove(element)
			flowCache.Unlock() // code below does not use flowCache any more
			atomic.AddInt32(&f.stats.CurrNumFlows, -1)
			flowExtra.setCurFlowInfo(flowExtra.recentTime, forceReportInterval, reportTolerance)
			calcCloseType(taggedFlow, flowExtra.flowState)
			if flowExtra.hasFlowAction {
				taggedFlow.TcpPerfStats = Report(flowExtra.metaFlowPerf, flowExtra.reversed, &f.perfCounter)
				f.pushFlowOutQueue(taggedFlow, false, int(f.timeoutCleanerCount))
			} else {
				ReleaseTaggedFlow(taggedFlow)
			}
			ReleaseFlowExtra(flowExtra)
		} else {
			if f.checkIfDoFlowPerf(flowExtra) {
				serverToClient := (meta.Direction == SERVER_TO_CLIENT)
				flowExtra.metaFlowPerf.Update(meta, flowExtra.reversed == serverToClient, flowExtra, &f.perfCounter)
			}
			flowCache.Unlock()
		}
	} else {
		if f.stats.CurrNumFlows >= f.flowLimitNum {
			f.stats.FloodDropPackets++
			flowCache.Unlock()
			return
		}
		flowExtra, _ = f.initTcpFlow(meta) // Flow不可能结束，忽略第二个返回值
		f.stats.TotalNumFlows++
		if f.checkIfDoFlowPerf(flowExtra) {
			flowExtra.metaFlowPerf.Update(meta, true, flowExtra, &f.perfCounter)
		}
		f.addFlow(flowCache, flowExtra)
		flowCache.Unlock()
		atomic.AddInt32(&f.stats.CurrNumFlows, 1)
	}
}

// FIXME: 此时Flow不可能结束，第二个返回值永远为False
func (f *FlowGenerator) initTcpFlow(meta *MetaPacket) (*FlowExtra, bool) {
	now := meta.Timestamp
	flowExtra := f.initFlow(meta, now)
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
	taggedFlow.FlowMetricsPeerSrc.TotalByteCount = uint64(meta.PacketLen)
	taggedFlow.FlowMetricsPeerSrc.ByteCount = uint64(meta.PacketLen)
	updatePlatformData(taggedFlow, meta.EndpointData, false)
	f.fillGeoInfo(taggedFlow)

	f.updateTCPDirection(meta, flowExtra, true)
	flowExtra.setMetaPacketActiveService(meta)

	flags = flags & TCP_FLAG_MASK
	if f.StatePreprocess(meta, flags) || meta.Invalid {
		flowExtra.timeout = exceptionTimeout
		flowExtra.flowState = FLOW_STATE_EXCEPTION
		return flowExtra, false
	}

	return flowExtra, f.updateFlowStateMachine(flowExtra, flags, meta.Direction == SERVER_TO_CLIENT)
}

func (f *FlowGenerator) updateTcpFlow(flowExtra *FlowExtra, meta *MetaPacket) bool {
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
	f.updateFlow(flowExtra, meta)

	f.updateTCPDirection(meta, flowExtra, false)
	flowExtra.setMetaPacketActiveService(meta)

	if f.StatePreprocess(meta, flags) || meta.Invalid {
		flowExtra.timeout = exceptionTimeout
		flowExtra.flowState = FLOW_STATE_EXCEPTION
		return false
	}
	return f.updateFlowStateMachine(flowExtra, flags, meta.Direction == SERVER_TO_CLIENT)
}

func (f *FlowGenerator) updateTCPDirection(meta *MetaPacket, flowExtra *FlowExtra, isFirstPacket bool) {
	srcKey := ServiceKey(int16(meta.EndpointData.SrcInfo.L3EpcId), meta.IpSrc, meta.PortSrc)
	dstKey := ServiceKey(int16(meta.EndpointData.DstInfo.L3EpcId), meta.IpDst, meta.PortDst)

	srcScore, dstScore := f.tcpServiceTable.GetTCPScore(isFirstPacket, meta.TcpData.Flags, srcKey, dstKey)
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
