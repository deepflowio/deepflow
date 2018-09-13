package flowgenerator

import (
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (f *FlowGenerator) processOtherIpPacket(meta *MetaPacket) {
	reply := false
	var flowExtra *FlowExtra
	flowKey := f.genFlowKey(meta)
	hash := f.getQuinTupleHash(flowKey)
	flowCache := f.hashMap[hash%HASH_MAP_SIZE]
	if flowExtra, reply = flowCache.keyMatch(meta, flowKey); flowExtra != nil {
		f.updateOtherIpFlow(flowExtra, meta, reply)
	} else {
		if f.stats.CurrNumFlows >= f.flowLimitNum {
			f.stats.FloodDropPackets++
			return
		}
		flowExtra = f.initOtherIpFlow(meta, flowKey)
		f.stats.TotalNumFlows++
		f.addFlow(flowCache, flowExtra)
		f.stats.CurrNumFlows++
	}
}

func (f *FlowGenerator) initOtherIpFlow(meta *MetaPacket, key *FlowKey) *FlowExtra {
	now := time.Duration(meta.Timestamp)
	flowExtra := f.initFlow(meta, key, now)
	taggedFlow := flowExtra.taggedFlow
	taggedFlow.FlowMetricsPeerSrc.ArrTime0 = now
	taggedFlow.FlowMetricsPeerSrc.ArrTimeLast = now
	taggedFlow.FlowMetricsPeerSrc.TotalPacketCount = 1
	taggedFlow.FlowMetricsPeerSrc.PacketCount = 1
	taggedFlow.FlowMetricsPeerSrc.TotalByteCount = uint64(meta.PacketLen)
	taggedFlow.FlowMetricsPeerSrc.ByteCount = uint64(meta.PacketLen)
	flowExtra.flowState = FLOW_STATE_ESTABLISHED
	flowExtra.timeout = f.TimeoutConfig.Opening
	return flowExtra
}

func (f *FlowGenerator) updateOtherIpFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) {
	f.updateFlow(flowExtra, meta, reply)
	if reply {
		flowExtra.timeout = f.TimeoutConfig.EstablishedRst
	}
}
