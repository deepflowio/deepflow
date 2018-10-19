package flowgenerator

import (
	"sync/atomic"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (f *FlowGenerator) processTcpPacket(meta *MetaPacket) {
	flowKey := f.genFlowKey(meta)
	hash := f.getQuinTupleHash(flowKey)
	flowCache := f.hashMap[hash%HASH_MAP_SIZE]
	flowCache.Lock()
	if flowExtra, reply, element := flowCache.keyMatch(meta, flowKey); flowExtra != nil {
		ok := false
		if ok, reply = f.updateTcpFlow(flowExtra, meta, reply); ok {
			flowCache.flowList.Remove(element)
			flowCache.Unlock() // code below does not use flowCache any more
			taggedFlow := flowExtra.taggedFlow
			atomic.AddInt32(&f.stats.CurrNumFlows, -1)
			flowExtra.setCurFlowInfo(flowExtra.recentTime, f.forceReportInterval)
			if f.servicePortDescriptor.judgeServiceDirection(taggedFlow, flowExtra.reversed) {
				flowExtra.reverseFlow()
				flowExtra.reversed = !flowExtra.reversed
			}
			flowExtra.calcCloseType(false)
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
		flowExtra, _, reply = f.initTcpFlow(meta, flowKey)
		f.stats.TotalNumFlows++
		if f.checkIfDoFlowPerf(flowExtra) {
			flowExtra.metaFlowPerf.Update(meta, reply, flowExtra, &f.perfCounter)
		}
		f.addFlow(flowCache, flowExtra)
		flowCache.Unlock()
		atomic.AddInt32(&f.stats.CurrNumFlows, 1)
	}
}

func (f *FlowGenerator) initTcpFlow(meta *MetaPacket, key *FlowKey) (*FlowExtra, bool, bool) {
	now := meta.Timestamp
	flowExtra := f.initFlow(meta, key, now)
	taggedFlow := flowExtra.taggedFlow
	var flags uint8 = 0
	if meta.TcpData != nil {
		flags = meta.TcpData.Flags
	}
	if flagEqual(flags&TCP_FLAG_MASK, TCP_SYN|TCP_ACK) {
		taggedFlow.IPSrc, taggedFlow.IPDst = taggedFlow.IPDst, taggedFlow.IPSrc
		taggedFlow.PortSrc, taggedFlow.PortDst = taggedFlow.PortDst, taggedFlow.PortSrc
		taggedFlow.TunnelInfo.Src, taggedFlow.TunnelInfo.Dst = taggedFlow.TunnelInfo.Dst, taggedFlow.TunnelInfo.Src
		taggedFlow.FlowMetricsPeerDst.ArrTime0 = now
		taggedFlow.FlowMetricsPeerDst.ArrTimeLast = now
		taggedFlow.FlowMetricsPeerDst.TotalPacketCount = 1
		taggedFlow.FlowMetricsPeerDst.PacketCount = 1
		taggedFlow.FlowMetricsPeerDst.TotalByteCount = uint64(meta.PacketLen)
		taggedFlow.FlowMetricsPeerDst.ByteCount = uint64(meta.PacketLen)
		flowExtra.updatePlatformData(meta, true)
		flowExtra.reversed = true
		return flowExtra, f.updateFlowStateMachine(flowExtra, flags, true, meta.Invalid), true
	} else {
		taggedFlow.FlowMetricsPeerSrc.ArrTime0 = now
		taggedFlow.FlowMetricsPeerSrc.ArrTimeLast = now
		taggedFlow.FlowMetricsPeerSrc.TotalPacketCount = 1
		taggedFlow.FlowMetricsPeerSrc.PacketCount = 1
		taggedFlow.FlowMetricsPeerSrc.TotalByteCount = uint64(meta.PacketLen)
		taggedFlow.FlowMetricsPeerSrc.ByteCount = uint64(meta.PacketLen)
		flowExtra.updatePlatformData(meta, false)
		return flowExtra, f.updateFlowStateMachine(flowExtra, flags, false, meta.Invalid), false
	}
}

func (f *FlowGenerator) updateTcpFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) (bool, bool) {
	flags := uint8(0)
	if meta.TcpData != nil {
		flags = meta.TcpData.Flags
	}
	if f.tryReverseFlow(flowExtra, meta, reply) {
		reply = !reply
	}
	f.updateFlow(flowExtra, meta, reply)
	return f.updateFlowStateMachine(flowExtra, flags, reply, meta.Invalid), reply
}
