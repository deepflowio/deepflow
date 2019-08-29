package flowgenerator

import (
	"sync/atomic"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (f *FlowGenerator) processTcpPacket(meta *MetaPacket) {
	hash := f.getQuinTupleHash(meta)
	flowCache := f.hashMap[hash%hashMapSize]
	flowCache.Lock()
	if flowExtra, reply, element := f.keyMatch(flowCache, meta); flowExtra != nil {
		ok := false
		taggedFlow := flowExtra.taggedFlow
		if ok, reply = f.updateTcpFlow(flowExtra, meta, reply); ok {
			flowCache.flowList.Remove(element)
			flowCache.Unlock() // code below does not use flowCache any more
			atomic.AddInt32(&f.stats.CurrNumFlows, -1)
			flowExtra.setCurFlowInfo(flowExtra.recentTime, forceReportInterval, reportTolerance)
			calcCloseType(taggedFlow, flowExtra.flowState)
			if flowExtra.isFlowAction {
				taggedFlow.TcpPerfStats = Report(flowExtra.metaFlowPerf, flowExtra.reversed, &f.perfCounter)
				f.flowOutQueue.Put(taggedFlow)
			} else {
				ReleaseTaggedFlow(taggedFlow)
			}
			ReleaseFlowExtra(flowExtra)
		} else {
			// reply is a sign relative to the flow direction, so if the flow is reversed then the sign should be changed
			if f.checkIfDoFlowPerf(flowExtra) {
				flowExtra.metaFlowPerf.Update(meta, flowExtra.reversed != reply, flowExtra, &f.perfCounter)
			}
			flowCache.Unlock()
		}
	} else {
		if f.stats.CurrNumFlows >= f.flowLimitNum {
			f.stats.FloodDropPackets++
			flowCache.Unlock()
			return
		}
		flowExtra, _, reply = f.initTcpFlow(meta)
		f.stats.TotalNumFlows++
		if f.checkIfDoFlowPerf(flowExtra) {
			flowExtra.metaFlowPerf.Update(meta, reply, flowExtra, &f.perfCounter)
		}
		f.addFlow(flowCache, flowExtra)
		flowCache.Unlock()
		atomic.AddInt32(&f.stats.CurrNumFlows, 1)
	}
}

func (f *FlowGenerator) initTcpFlow(meta *MetaPacket) (*FlowExtra, bool, bool) {
	now := meta.Timestamp
	flowExtra := f.initFlow(meta, now)
	taggedFlow := flowExtra.taggedFlow
	reply := false
	flags := uint8(0)
	if meta.TcpData != nil {
		flags = meta.TcpData.Flags
	}
	if flagEqual(flags, TCP_SYN|TCP_ACK) {
		reply = true
		flowExtra.reversed = !flowExtra.reversed
		taggedFlow.MACSrc, taggedFlow.MACDst = taggedFlow.MACDst, taggedFlow.MACSrc
		taggedFlow.IPSrc, taggedFlow.IPDst = taggedFlow.IPDst, taggedFlow.IPSrc
		taggedFlow.PortSrc, taggedFlow.PortDst = taggedFlow.PortDst, taggedFlow.PortSrc
		taggedFlow.TunnelInfo.Src, taggedFlow.TunnelInfo.Dst = taggedFlow.TunnelInfo.Dst, taggedFlow.TunnelInfo.Src
		taggedFlow.FlowMetricsPeerDst.TCPFlags |= flags
		taggedFlow.FlowMetricsPeerDst.ArrTime0 = now
		taggedFlow.FlowMetricsPeerDst.ArrTimeLast = now
		taggedFlow.FlowMetricsPeerDst.TotalPacketCount = 1
		taggedFlow.FlowMetricsPeerDst.PacketCount = 1
		taggedFlow.FlowMetricsPeerDst.TotalByteCount = uint64(meta.PacketLen)
		taggedFlow.FlowMetricsPeerDst.ByteCount = uint64(meta.PacketLen)
		reverseFlowTag(taggedFlow)
		updatePlatformData(taggedFlow, meta.EndpointData, reply)
		f.fillGeoInfo(taggedFlow)
	} else {
		taggedFlow.FlowMetricsPeerSrc.TCPFlags |= flags
		taggedFlow.FlowMetricsPeerSrc.ArrTime0 = now
		taggedFlow.FlowMetricsPeerSrc.ArrTimeLast = now
		taggedFlow.FlowMetricsPeerSrc.TotalPacketCount = 1
		taggedFlow.FlowMetricsPeerSrc.PacketCount = 1
		taggedFlow.FlowMetricsPeerSrc.TotalByteCount = uint64(meta.PacketLen)
		taggedFlow.FlowMetricsPeerSrc.ByteCount = uint64(meta.PacketLen)
		updatePlatformData(taggedFlow, meta.EndpointData, reply)
		f.fillGeoInfo(taggedFlow)
	}

	f.updateTCPDirection(meta, flowExtra, true)
	flowExtra.setMetaPacketDirection(meta)

	flags = flags & TCP_FLAG_MASK
	if f.StatePreprocess(meta, flags) || meta.Invalid {
		flowExtra.timeout = exceptionTimeout
		flowExtra.flowState = FLOW_STATE_EXCEPTION
		return flowExtra, false, reply
	}

	return flowExtra, f.updateFlowStateMachine(flowExtra, flags, reply), reply
}

func (f *FlowGenerator) updateTcpFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) (bool, bool) {
	taggedFlow := flowExtra.taggedFlow
	flags := uint8(0)
	if meta.TcpData != nil {
		flags = meta.TcpData.Flags
	}
	if reply {
		taggedFlow.FlowMetricsPeerDst.TCPFlags |= flags
	} else {
		taggedFlow.FlowMetricsPeerSrc.TCPFlags |= flags
	}
	f.updateFlow(flowExtra, meta, reply)

	// 根据SYN|ACK判断方向
	flags = flags & TCP_FLAG_MASK
	if flagEqual(flags, TCP_SYN|TCP_ACK) && !reply {
		reply = true
		flowExtra.reverseFlow()
		flowExtra.reversed = !flowExtra.reversed
	}
	f.updateTCPDirection(meta, flowExtra, false)
	flowExtra.setMetaPacketDirection(meta)

	if f.StatePreprocess(meta, flags) || meta.Invalid {
		flowExtra.timeout = exceptionTimeout
		flowExtra.flowState = FLOW_STATE_EXCEPTION
		return false, reply
	}
	return f.updateFlowStateMachine(flowExtra, flags, reply), reply
}

func (f *FlowGenerator) updateTCPDirection(meta *MetaPacket, flowExtra *FlowExtra, isFirstPacket bool) {
	srcKey := ServiceKey(int16(meta.EndpointData.SrcInfo.L3EpcId), meta.IpSrc, meta.PortSrc)
	dstKey := ServiceKey(int16(meta.EndpointData.DstInfo.L3EpcId), meta.IpDst, meta.PortDst)

	srcScore, dstScore := f.tcpServiceTable.GetTCPScore(isFirstPacket, meta.TcpData.Flags, srcKey, dstKey)
	if flowExtra.getMetaPacketDirection(meta) == SERVER_TO_CLIENT {
		srcScore, dstScore = dstScore, srcScore
	}
	if !IsClientToServer(srcScore, dstScore) {
		flowExtra.reverseFlow()
		flowExtra.reversed = !flowExtra.reversed
	}
	flowExtra.taggedFlow.Flow.IsActiveService = IsActiveService(srcScore, dstScore)
}
