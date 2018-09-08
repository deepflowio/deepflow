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
			flowExtra.setCurFlowInfo(meta.Timestamp, f.forceReportIntervalSec)
			flowExtra.taggedFlow.CloseType = CLOSE_TYPE_FLOOD
			if f.servicePortDescriptor.judgeServiceDirection(taggedFlow.PortSrc, taggedFlow.PortDst) {
				flowExtra.reverseFlow()
				flowExtra.reversed = !flowExtra.reversed
			}
			f.flowOutQueue.Put(taggedFlow)
			flowExtra.reset()
			f.FlowExtraPool.Put(flowExtra)
		} else {
			f.stats.CurrNumFlows++
		}
	}
}

func (f *FlowGenerator) initUdpFlow(meta *MetaPacket, key *FlowKey) *FlowExtra {
	now := time.Duration(meta.Timestamp)
	flowExtra := f.initFlow(meta, key, now)
	flowExtra.flowState = FLOW_STATE_ESTABLISHED
	flowExtra.timeoutSec = f.TimeoutConfig.Opening
	return flowExtra
}

func (f *FlowGenerator) updateUdpFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) {
	f.updateFlow(flowExtra, meta, reply)
	if reply {
		flowExtra.timeoutSec = f.TimeoutConfig.EstablishedRst
	}
}
