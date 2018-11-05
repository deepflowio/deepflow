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
			flowExtra.setCurFlowInfo(flowExtra.recentTime, f.forceReportInterval, f.reportTolerance)
			if f.checkTcpServiceReverse(taggedFlow, flowExtra.reversed) {
				flowExtra.reverseFlow()
				flowExtra.reversed = !flowExtra.reversed
			}
			calcCloseType(taggedFlow, flowExtra.flowState)
			taggedFlow.TcpPerfStats = Report(flowExtra.metaFlowPerf, flowExtra.reversed, &f.perfCounter)
			ReleaseFlowExtra(flowExtra)
			f.flowOutQueue.Put(taggedFlow)
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
	flags := meta.TcpData.Flags
	if flagEqual(flags, TCP_SYN|TCP_ACK) {
		reply = true
		flowExtra.reversed = reply
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
		updatePlatformData(taggedFlow, meta.EndpointData, reply)
	} else {
		taggedFlow.FlowMetricsPeerSrc.TCPFlags |= flags
		taggedFlow.FlowMetricsPeerSrc.ArrTime0 = now
		taggedFlow.FlowMetricsPeerSrc.ArrTimeLast = now
		taggedFlow.FlowMetricsPeerSrc.TotalPacketCount = 1
		taggedFlow.FlowMetricsPeerSrc.PacketCount = 1
		taggedFlow.FlowMetricsPeerSrc.TotalByteCount = uint64(meta.PacketLen)
		taggedFlow.FlowMetricsPeerSrc.ByteCount = uint64(meta.PacketLen)
		updatePlatformData(taggedFlow, meta.EndpointData, reply)
	}
	if f.StatePreprocess(meta, flags) || meta.Invalid {
		flowExtra.timeout = f.TimeoutConfig.Exception
		flowExtra.flowState = FLOW_STATE_EXCEPTION
		return flowExtra, false, reply
	}
	return flowExtra, f.updateFlowStateMachine(flowExtra, flags, reply), reply
}

func (f *FlowGenerator) updateTcpFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) (bool, bool) {
	taggedFlow := flowExtra.taggedFlow
	flags := meta.TcpData.Flags
	if reply {
		taggedFlow.FlowMetricsPeerDst.TCPFlags |= flags
	} else {
		taggedFlow.FlowMetricsPeerSrc.TCPFlags |= flags
	}
	f.updateFlow(flowExtra, meta, reply)
	reply = reply != f.tryReverseFlow(flowExtra, meta, reply)
	if f.StatePreprocess(meta, flags) || meta.Invalid {
		flowExtra.timeout = f.TimeoutConfig.Exception
		flowExtra.flowState = FLOW_STATE_EXCEPTION
		return false, reply
	}
	return f.updateFlowStateMachine(flowExtra, flags, reply), reply
}

// return true if a flow should be reversed
func (f *FlowGenerator) checkTcpServiceReverse(taggedFlow *TaggedFlow, reversed bool) ServiceStatus {
	if reversed {
		return false
	}
	srcOk := f.ServiceManager.getStatus(taggedFlow.FlowMetricsPeerSrc.L3EpcID, taggedFlow.IPSrc, taggedFlow.PortSrc)
	if !srcOk {
		return false
	}
	dstOk := f.ServiceManager.getStatus(taggedFlow.FlowMetricsPeerDst.L3EpcID, taggedFlow.IPDst, taggedFlow.PortDst)
	if !dstOk {
		return true
	} else if taggedFlow.PortDst <= taggedFlow.PortSrc {
		return false
	}
	return true
}
