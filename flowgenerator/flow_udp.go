package flowgenerator

import (
	"sync/atomic"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (f *FlowGenerator) processUdpPacket(meta *MetaPacket) {
	hash := f.getQuinTupleHash(meta)
	flowCache := f.hashMap[hash%hashMapSize]
	flowCache.Lock()
	if flowExtra, reply, _ := f.keyMatch(flowCache, meta); flowExtra != nil {
		f.updateUdpFlow(flowExtra, meta, reply)
	} else {
		if f.stats.CurrNumFlows >= f.flowLimitNum {
			f.stats.FloodDropPackets++
			flowCache.Unlock()
			return
		}
		flowExtra = f.initUdpFlow(meta)
		f.stats.TotalNumFlows++
		f.addFlow(flowCache, flowExtra)
		atomic.AddInt32(&f.stats.CurrNumFlows, 1)
	}
	flowCache.Unlock()
}

func (f *FlowGenerator) initUdpFlow(meta *MetaPacket) *FlowExtra {
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
	f.fillGeoInfo(taggedFlow)
	flowExtra.flowState = FLOW_STATE_ESTABLISHED
	flowExtra.timeout = openingTimeout
	f.updateUDPDirection(meta, flowExtra, true)
	flowExtra.setMetaPacketDirection(meta)
	return flowExtra
}

func (f *FlowGenerator) updateUdpFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) {
	f.updateFlow(flowExtra, meta, reply)
	if reply {
		flowExtra.timeout = establishedRstTimeout
	}
	f.updateUDPDirection(meta, flowExtra, false)
	flowExtra.setMetaPacketDirection(meta)
}

func (f *FlowGenerator) updateUDPDirection(meta *MetaPacket, flowExtra *FlowExtra, isFirstPacket bool) {
	srcKey := ServiceKey(int16(meta.EndpointData.SrcInfo.L3EpcId), meta.IpSrc, meta.PortSrc)
	dstKey := ServiceKey(int16(meta.EndpointData.DstInfo.L3EpcId), meta.IpDst, meta.PortDst)

	srcScore, dstScore := f.udpServiceTable.GetUDPScore(isFirstPacket, srcKey, dstKey)
	if flowExtra.getMetaPacketDirection(meta) == SERVER_TO_CLIENT {
		srcScore, dstScore = dstScore, srcScore
	}
	if !IsClientToServer(srcScore, dstScore) {
		flowExtra.reverseFlow()
	}
	flowExtra.taggedFlow.Flow.IsActiveService = IsActiveService(srcScore, dstScore)
}
