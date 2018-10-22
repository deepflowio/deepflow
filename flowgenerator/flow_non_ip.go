package flowgenerator

import (
	"sync/atomic"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (f *FlowGenerator) getNonIpQuinTupleHash(flowKey *FlowKey) uint64 {
	return flowKey.MACSrc ^ flowKey.MACDst
}

func (f *FlowCache) keyMatchForNonIp(meta *MetaPacket, key *FlowKey) (*FlowExtra, bool) {
	for e := f.flowList.Front(); e != nil; e = e.Next() {
		flowExtra := e.Value
		taggedFlow := flowExtra.taggedFlow
		flowMacSrc, flowMacDst := taggedFlow.MACSrc, taggedFlow.MACDst
		if flowMacSrc == meta.MacSrc && flowMacDst == meta.MacDst {
			return flowExtra, false
		}
		if flowMacSrc == meta.MacDst && flowMacDst == meta.MacSrc {
			return flowExtra, true
		}
	}
	return nil, false
}

func (f *FlowGenerator) processNonIpPacket(meta *MetaPacket) {
	flowKey := f.genFlowKey(meta)
	hash := f.getNonIpQuinTupleHash(flowKey)
	flowCache := f.hashMap[hash%hashMapSize]
	flowCache.Lock()
	if flowExtra, reply := flowCache.keyMatchForNonIp(meta, flowKey); flowExtra != nil {
		f.updateNonIpFlow(flowExtra, meta, reply)
	} else {
		if f.stats.CurrNumFlows >= f.flowLimitNum {
			f.stats.FloodDropPackets++
			flowCache.Unlock()
			return
		}
		flowExtra = f.initNonIpFlow(meta, flowKey)
		f.stats.TotalNumFlows++
		f.addFlow(flowCache, flowExtra)
		atomic.AddInt32(&f.stats.CurrNumFlows, 1)
	}
	flowCache.Unlock()
}

func (f *FlowGenerator) initNonIpFlow(meta *MetaPacket, key *FlowKey) *FlowExtra {
	now := meta.Timestamp
	flowExtra := f.initFlow(meta, key, now)
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

func (f *FlowGenerator) updateNonIpFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) {
	f.updateFlow(flowExtra, meta, reply)
	if reply {
		flowExtra.timeout = f.TimeoutConfig.EstablishedRst
	}
}
