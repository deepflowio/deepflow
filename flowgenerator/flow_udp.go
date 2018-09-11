package flowgenerator

import (
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (f *FlowGenerator) processUdpPacket(meta *MetaPacket) {
	reply := false
	var flowExtra *FlowExtra
	flowKey := f.genFlowKey(meta)
	hash := f.getQuinTupleHash(flowKey)
	flowCache := f.hashMap[hash%HASH_MAP_SIZE]
	if flowExtra, reply = flowCache.keyMatch(meta, flowKey); flowExtra != nil {
		f.updateUdpFlow(flowExtra, meta, reply)
	} else {
		flowExtra = f.initUdpFlow(meta, flowKey)
		taggedFlow := flowExtra.taggedFlow
		f.stats.TotalNumFlows++
		if flowExtra == f.addFlow(flowCache, flowExtra) {
			// reach limit and output directly
			flowExtra.setCurFlowInfo(meta.Timestamp, f.forceReportInterval)
			flowExtra.taggedFlow.CloseType = CLOSE_TYPE_FLOOD
			if f.servicePortDescriptor.judgeServiceDirection(taggedFlow.PortSrc, taggedFlow.PortDst) {
				flowExtra.reverseFlow()
				flowExtra.reversed = !flowExtra.reversed
			}
			f.flowOutQueue.Put(taggedFlow)
			flowExtra.reset()
		} else {
			f.stats.CurrNumFlows++
		}
	}
}

func (f *FlowGenerator) initUdpFlow(meta *MetaPacket, key *FlowKey) *FlowExtra {
	now := time.Duration(meta.Timestamp)
	flowExtra := f.initFlow(meta, key, now)
	taggedFlow := flowExtra.taggedFlow
	taggedFlow.FlowMetricsPeerSrc.ArrTime0 = now
	taggedFlow.FlowMetricsPeerSrc.ArrTimeLast = now
	taggedFlow.FlowMetricsPeerSrc.TotalPacketCount = 1
	taggedFlow.FlowMetricsPeerSrc.PacketCount = 1
	taggedFlow.FlowMetricsPeerSrc.TotalByteCount = uint64(meta.PacketLen)
	taggedFlow.FlowMetricsPeerSrc.ByteCount = uint64(meta.PacketLen)
	flowExtra.updatePlatformData(meta, false)
	flowExtra.flowState = FLOW_STATE_ESTABLISHED
	flowExtra.timeout = f.TimeoutConfig.Opening
	return flowExtra
}

func (f *FlowGenerator) updateUdpFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) {
	f.updateFlow(flowExtra, meta, reply)
	if reply {
		flowExtra.timeout = f.TimeoutConfig.EstablishedRst
	}
}
