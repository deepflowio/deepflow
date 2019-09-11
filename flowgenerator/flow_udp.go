package flowgenerator

import (
	"sync/atomic"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (f *FlowGenerator) processUdpPacket(meta *MetaPacket) {
	hash := f.getQuinTupleHash(meta)
	flowCache := f.hashMap[hash%hashMapSize]
	flowCache.Lock()
	if flowExtra, _ := f.keyMatch(flowCache, meta); flowExtra != nil {
		f.updateUdpFlow(flowExtra, meta)
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
	flowExtra.setMetaPacketActiveService(meta)
	return flowExtra
}

func (f *FlowGenerator) updateUdpFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	f.updateFlow(flowExtra, meta)
	if flowExtra.taggedFlow.FlowMetricsPeerSrc.PacketCount > 0 && flowExtra.taggedFlow.FlowMetricsPeerDst.PacketCount > 0 {
		flowExtra.timeout = establishedRstTimeout
	}
	f.updateUDPDirection(meta, flowExtra, false)
	flowExtra.setMetaPacketActiveService(meta)
}

func (f *FlowGenerator) updateUDPDirection(meta *MetaPacket, flowExtra *FlowExtra, isFirstPacket bool) {
	srcKey := ServiceKey(int16(meta.EndpointData.SrcInfo.L3EpcId), meta.IpSrc, meta.PortSrc)
	dstKey := ServiceKey(int16(meta.EndpointData.DstInfo.L3EpcId), meta.IpDst, meta.PortDst)

	srcScore, dstScore := f.udpServiceTable.GetUDPScore(isFirstPacket, srcKey, dstKey)
	if meta.Direction == SERVER_TO_CLIENT {
		srcScore, dstScore = dstScore, srcScore
	}
	if !IsClientToServer(srcScore, dstScore) {
		flowExtra.reverseFlow()
		flowExtra.reversed = !flowExtra.reversed
		meta.Direction = (CLIENT_TO_SERVER + SERVER_TO_CLIENT) - meta.Direction // reverse
	}
	flowExtra.taggedFlow.Flow.IsActiveService = IsActiveService(srcScore, dstScore)
}
