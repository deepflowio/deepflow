package flowgenerator

import (
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func updateFlowTag(taggedFlow *TaggedFlow, meta *MetaPacket) {
	taggedFlow.PolicyData = meta.PolicyData
	endpointdata := meta.EndpointData
	if endpointdata == nil {
		log.Warning("Unexpected nil packet endpointData")
		return
	}
	taggedFlow.GroupIDs0 = endpointdata.SrcInfo.GroupIds
	taggedFlow.GroupIDs1 = endpointdata.DstInfo.GroupIds
}

func (m *FlowMap) genFlowId(timestamp uint64) uint64 {
	return ((uint64(m.id) & THREAD_FLOW_ID_MASK) << 32) | ((timestamp & TIMER_FLOW_ID_MASK) << 32) | (m.totalFlow & COUNTER_FLOW_ID_MASK)
}

func (m *FlowMap) initFlow(flowExtra *FlowExtra, meta *MetaPacket, now time.Duration) {
	meta.Direction = CLIENT_TO_SERVER // 初始认为是C2S，流匹配、流方向矫正均会会更新此值

	taggedFlow := AcquireTaggedFlow()
	taggedFlow.Exporter = meta.Exporter
	taggedFlow.MACSrc = meta.MacSrc
	taggedFlow.MACDst = meta.MacDst
	taggedFlow.IPSrc = meta.IpSrc
	taggedFlow.IPDst = meta.IpDst
	taggedFlow.Proto = meta.Protocol
	taggedFlow.PortSrc = meta.PortSrc
	taggedFlow.PortDst = meta.PortDst
	taggedFlow.InPort = meta.InPort
	if tunnel := meta.Tunnel; tunnel != nil {
		taggedFlow.TunnelInfo = *tunnel
	} else {
		taggedFlow.TunnelInfo = TunnelInfo{}
	}
	taggedFlow.FlowID = m.genFlowId(uint64(now))
	taggedFlow.TimeBitmap = getBitmap(now)
	taggedFlow.StartTime = now
	taggedFlow.EndTime = now
	taggedFlow.PacketStatTime = now
	taggedFlow.VLAN = meta.Vlan
	taggedFlow.EthType = meta.EthType
	taggedFlow.QueueHash = meta.QueueHash
	updateFlowTag(taggedFlow, meta)

	flowExtra.taggedFlow = taggedFlow
	flowExtra.flowState = FLOW_STATE_RAW
	flowExtra.minArrTime = now
	flowExtra.recentTime = now
	flowExtra.reported = false
	flowExtra.reversed = false
	flowExtra.packetInTick = true
	flowExtra.packetInCycle = true
}

func (m *FlowMap) updateFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	taggedFlow := flowExtra.taggedFlow
	bytes := uint64(meta.PacketLen)
	packetTimestamp := meta.Timestamp
	startTime := taggedFlow.StartTime
	if packetTimestamp < flowExtra.recentTime || packetTimestamp < startTime {
		packetTimestamp = timeMax(flowExtra.recentTime, startTime)
	}
	flowExtra.recentTime = packetTimestamp
	flowExtra.taggedFlow.PacketStatTime = meta.Timestamp
	flowExtra.packetInTick = true
	if !flowExtra.packetInCycle {
		flowExtra.packetInCycle = true
		updateFlowTag(taggedFlow, meta)
		if meta.Direction == SERVER_TO_CLIENT {
			reverseFlowTag(taggedFlow)
		}
		updatePlatformData(taggedFlow, meta.EndpointData, meta.Direction == SERVER_TO_CLIENT)
	}
	if meta.Direction == SERVER_TO_CLIENT {
		if taggedFlow.FlowMetricsPeerDst.TotalPacketCount == 0 {
			taggedFlow.FlowMetricsPeerDst.ArrTime0 = packetTimestamp
		}
		taggedFlow.FlowMetricsPeerDst.ArrTimeLast = packetTimestamp
		taggedFlow.FlowMetricsPeerDst.TickPacketCount++
		taggedFlow.FlowMetricsPeerDst.PacketCount++
		taggedFlow.FlowMetricsPeerDst.TotalPacketCount++
		taggedFlow.FlowMetricsPeerDst.TickByteCount += bytes
		taggedFlow.FlowMetricsPeerDst.ByteCount += bytes
		taggedFlow.FlowMetricsPeerDst.TotalByteCount += bytes
	} else {
		if taggedFlow.FlowMetricsPeerSrc.TotalPacketCount == 0 {
			taggedFlow.FlowMetricsPeerSrc.ArrTime0 = packetTimestamp
		}
		taggedFlow.FlowMetricsPeerSrc.ArrTimeLast = packetTimestamp
		taggedFlow.FlowMetricsPeerSrc.TickPacketCount++
		taggedFlow.FlowMetricsPeerSrc.PacketCount++
		taggedFlow.FlowMetricsPeerSrc.TotalPacketCount++
		taggedFlow.FlowMetricsPeerSrc.TickByteCount += bytes
		taggedFlow.FlowMetricsPeerSrc.ByteCount += bytes
		taggedFlow.FlowMetricsPeerSrc.TotalByteCount += bytes
	}
	// a flow will report every minute and StartTime will be reset, so the value could not be overflow
	taggedFlow.TimeBitmap |= getBitmap(packetTimestamp)
}

func updatePlatformData(taggedFlow *TaggedFlow, endpointData *EndpointData, serverToClient bool) {
	if endpointData == nil {
		log.Warning("Unexpected nil packet endpointData")
		return
	}
	var srcInfo, dstInfo *EndpointInfo
	if serverToClient {
		srcInfo = endpointData.DstInfo
		dstInfo = endpointData.SrcInfo
	} else {
		srcInfo = endpointData.SrcInfo
		dstInfo = endpointData.DstInfo
	}
	taggedFlow.FlowMetricsPeerSrc.EpcID = srcInfo.L2EpcId
	taggedFlow.FlowMetricsPeerSrc.DeviceType = DeviceType(srcInfo.L2DeviceType)
	taggedFlow.FlowMetricsPeerSrc.DeviceID = srcInfo.L2DeviceId
	taggedFlow.FlowMetricsPeerSrc.IsL2End = srcInfo.L2End
	taggedFlow.FlowMetricsPeerSrc.IsL3End = srcInfo.L3End
	taggedFlow.FlowMetricsPeerSrc.L3EpcID = srcInfo.L3EpcId
	taggedFlow.FlowMetricsPeerSrc.L3DeviceType = DeviceType(srcInfo.L3DeviceType)
	taggedFlow.FlowMetricsPeerSrc.L3DeviceID = srcInfo.L3DeviceId
	taggedFlow.FlowMetricsPeerSrc.Host = srcInfo.HostIp
	taggedFlow.FlowMetricsPeerSrc.SubnetID = srcInfo.SubnetId
	taggedFlow.FlowMetricsPeerDst.EpcID = dstInfo.L2EpcId
	taggedFlow.FlowMetricsPeerDst.DeviceType = DeviceType(dstInfo.L2DeviceType)
	taggedFlow.FlowMetricsPeerDst.DeviceID = dstInfo.L2DeviceId
	taggedFlow.FlowMetricsPeerDst.IsL2End = dstInfo.L2End
	taggedFlow.FlowMetricsPeerDst.IsL3End = dstInfo.L3End
	taggedFlow.FlowMetricsPeerDst.L3EpcID = dstInfo.L3EpcId
	taggedFlow.FlowMetricsPeerDst.L3DeviceType = DeviceType(dstInfo.L3DeviceType)
	taggedFlow.FlowMetricsPeerDst.L3DeviceID = dstInfo.L3DeviceId
	taggedFlow.FlowMetricsPeerDst.Host = dstInfo.HostIp
	taggedFlow.FlowMetricsPeerDst.SubnetID = dstInfo.SubnetId
}

// reversePolicyData will return a clone of the current PolicyData
func reversePolicyData(policyData *PolicyData) *PolicyData {
	if policyData == nil {
		return nil
	}
	newPolicyData := ClonePolicyData(policyData)
	for i, aclAction := range newPolicyData.AclActions {
		newPolicyData.AclActions[i] = aclAction.ReverseDirection()
	}
	for i, _ := range newPolicyData.AclGidBitmaps {
		newPolicyData.AclGidBitmaps[i].ReverseGroupType()
	}
	return newPolicyData
}

func reverseFlowTag(taggedFlow *TaggedFlow) {
	taggedFlow.GroupIDs0, taggedFlow.GroupIDs1 = taggedFlow.GroupIDs1, taggedFlow.GroupIDs0
	taggedFlow.PolicyData = reversePolicyData(taggedFlow.PolicyData)
}

func (f *FlowMap) checkIfDoFlowPerf(flowExtra *FlowExtra) bool {
	if flowExtra.taggedFlow.PolicyData != nil && flowExtra.taggedFlow.PolicyData.ActionFlags&FLOW_PERF_ACTION_FLAGS != 0 {
		if flowExtra.metaFlowPerf == nil {
			flowExtra.metaFlowPerf = AcquireMetaFlowPerf()
		}
		return true
	}

	return false
}
