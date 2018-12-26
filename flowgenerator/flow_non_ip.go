package flowgenerator

import (
	"sync/atomic"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (f *FlowGenerator) getNonIpQuinTupleHash(meta *MetaPacket) uint64 {
	return meta.MacSrc ^ meta.MacDst
}

func (f *FlowCache) keyMatchForNonIp(meta *MetaPacket) (*FlowExtra, bool) {
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
	hash := f.getNonIpQuinTupleHash(meta)
	flowCache := f.hashMap[hash%hashMapSize]
	flowCache.Lock()
	if flowExtra, reply := flowCache.keyMatchForNonIp(meta); flowExtra != nil {
		f.updateNonIpFlow(flowExtra, meta, reply)
	} else {
		if f.stats.CurrNumFlows >= f.flowLimitNum {
			f.stats.FloodDropPackets++
			flowCache.Unlock()
			return
		}
		flowExtra = f.initNonIpFlow(meta)
		f.stats.TotalNumFlows++
		f.addFlow(flowCache, flowExtra)
		atomic.AddInt32(&f.stats.CurrNumFlows, 1)
	}
	flowCache.Unlock()
}

func (f *FlowGenerator) initNonIpFlow(meta *MetaPacket) *FlowExtra {
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
	flowExtra.timeout = openingTimeout
	return flowExtra
}

func (f *FlowGenerator) updateNonIpFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) {
	f.updateFlow(flowExtra, meta, reply)
	if reply {
		flowExtra.timeout = establishedRstTimeout
	}
}
