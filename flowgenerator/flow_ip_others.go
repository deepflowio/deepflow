package flowgenerator

import (
	"sync/atomic"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (f *FlowGenerator) processOtherIpPacket(meta *MetaPacket) {
	hash := f.getQuinTupleHash(meta)
	flowCache := f.hashMap[hash%hashMapSize]
	flowCache.Lock()
	if flowExtra, reply, _ := flowCache.keyMatch(meta); flowExtra != nil {
		f.updateOtherIpFlow(flowExtra, meta, reply)
	} else {
		if f.stats.CurrNumFlows >= f.flowLimitNum {
			f.stats.FloodDropPackets++
			flowCache.Unlock()
			return
		}
		flowExtra = f.initOtherIpFlow(meta)
		f.stats.TotalNumFlows++
		f.addFlow(flowCache, flowExtra)
		atomic.AddInt32(&f.stats.CurrNumFlows, 1)
	}
	flowCache.Unlock()
}

func (f *FlowGenerator) initOtherIpFlow(meta *MetaPacket) *FlowExtra {
	now := meta.Timestamp
	flowExtra := f.initFlow(meta, now)
	taggedFlow := flowExtra.taggedFlow
	taggedFlow.FlowMetricsPeerSrc.ArrTime0 = now
	taggedFlow.FlowMetricsPeerSrc.ArrTimeLast = now
	taggedFlow.FlowMetricsPeerSrc.TotalPacketCount = 1
	taggedFlow.FlowMetricsPeerSrc.PacketCount = 1
	taggedFlow.FlowMetricsPeerSrc.TotalByteCount = uint64(meta.PacketLen)
	taggedFlow.FlowMetricsPeerSrc.ByteCount = uint64(meta.PacketLen)
	updatePlatformData(taggedFlow, meta.EndpointData, false)
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
