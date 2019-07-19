package flowgenerator

import (
	"sync/atomic"
	"time"

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
	clientHash := (uint64(meta.IpSrc) << 16) | uint64(meta.PortSrc)
	serviceKey := genServiceKey(taggedFlow.FlowMetricsPeerDst.L3EpcID, taggedFlow.IPDst, taggedFlow.PortDst)
	getUdpServiceManager(f.index).hitUdpStatus(serviceKey, clientHash, meta.Timestamp)
	flowExtra.flowState = FLOW_STATE_ESTABLISHED
	flowExtra.timeout = openingTimeout
	if f.checkUdpServiceReverse(taggedFlow, flowExtra.reversed, now) {
		flowExtra.reverseFlow()
	}
	flowExtra.setMetaPacketDirection(meta)
	return flowExtra
}

func (f *FlowGenerator) updateUdpFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) {
	f.updateFlow(flowExtra, meta, reply)
	if reply {
		flowExtra.timeout = establishedRstTimeout
	}
	flowExtra.setMetaPacketDirection(meta)
}

func (f *FlowGenerator) checkUdpServiceReverse(taggedFlow *TaggedFlow, reversed bool, now time.Duration) bool {
	if reversed {
		return false
	}
	serviceKey := genServiceKey(taggedFlow.FlowMetricsPeerSrc.L3EpcID, taggedFlow.IPSrc, taggedFlow.PortSrc)
	srcOk := getUdpServiceManager(f.index).getUdpStatus(serviceKey, taggedFlow.PortSrc, now)
	if !srcOk {
		return false
	}
	serviceKey = genServiceKey(taggedFlow.FlowMetricsPeerDst.L3EpcID, taggedFlow.IPDst, taggedFlow.PortDst)
	dstOk := getUdpServiceManager(f.index).getUdpStatus(serviceKey, taggedFlow.PortDst, now)
	if !dstOk {
		return true
	} else if taggedFlow.PortDst <= taggedFlow.PortSrc {
		return false
	}
	return true
}
