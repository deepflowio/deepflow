package flowgenerator

import (
	"github.com/google/gopacket/layers"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
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

func (m *FlowMap) initFlow(flowExtra *FlowExtra, meta *MetaPacket) {
	now := meta.Timestamp
	meta.Direction = CLIENT_TO_SERVER // 初始认为是C2S，流匹配、流方向矫正均会会更新此值

	taggedFlow := AcquireTaggedFlow()
	taggedFlow.Exporter = meta.Exporter
	taggedFlow.MACSrc = meta.MacSrc
	taggedFlow.MACDst = meta.MacDst
	taggedFlow.IPSrc = meta.IpSrc
	taggedFlow.IPDst = meta.IpDst
	if meta.EthType == layers.EthernetTypeIPv6 {
		taggedFlow.IP6Src = meta.Ip6Src
		taggedFlow.IP6Dst = meta.Ip6Dst
	}
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
	taggedFlow.PacketStatTime = now / _PACKET_STAT_INTERVAL * _PACKET_STAT_INTERVAL
	taggedFlow.FlowStatTime = now / _FLOW_STAT_INTERVAL * _FLOW_STAT_INTERVAL
	taggedFlow.VLAN = meta.Vlan
	taggedFlow.EthType = meta.EthType
	taggedFlow.QueueHash = meta.QueueHash
	taggedFlow.IsNewFlow = true
	updateFlowTag(taggedFlow, meta)

	flowExtra.taggedFlow = taggedFlow
	flowExtra.flowState = FLOW_STATE_RAW
	flowExtra.minArrTime = now
	flowExtra.recentTime = now
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
	if !flowExtra.packetInTick { // PacketStatTime取整至包统计时间的开始，只需要赋值一次，且使用包的时间戳
		flowExtra.packetInTick = true
		flowExtra.taggedFlow.PacketStatTime = meta.Timestamp / _PACKET_STAT_INTERVAL * _PACKET_STAT_INTERVAL
	}
	if !flowExtra.packetInCycle {
		flowExtra.packetInCycle = true
		updateFlowTag(taggedFlow, meta)
		if meta.Direction == SERVER_TO_CLIENT {
			reverseFlowTag(taggedFlow)
		}
		updatePlatformData(taggedFlow, meta.EndpointData, meta.Direction == SERVER_TO_CLIENT)
	}
	flowMetricsPeer := &taggedFlow.FlowMetricsPeers[meta.Direction]
	flowMetricsPeer.TickPacketCount++
	flowMetricsPeer.PacketCount++
	flowMetricsPeer.TotalPacketCount++
	flowMetricsPeer.TickByteCount += bytes
	flowMetricsPeer.ByteCount += bytes
	flowMetricsPeer.TotalByteCount += bytes
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
	flowMetricsPeerSrc := &taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST]
	flowMetricsPeerSrc.EpcID = srcInfo.L2EpcId
	flowMetricsPeerSrc.DeviceType = DeviceType(srcInfo.L2DeviceType)
	flowMetricsPeerSrc.DeviceID = srcInfo.L2DeviceId
	flowMetricsPeerSrc.IsL2End = srcInfo.L2End
	flowMetricsPeerSrc.IsL3End = srcInfo.L3End
	flowMetricsPeerSrc.L3EpcID = srcInfo.L3EpcId
	flowMetricsPeerSrc.L3DeviceType = DeviceType(srcInfo.L3DeviceType)
	flowMetricsPeerSrc.L3DeviceID = srcInfo.L3DeviceId
	flowMetricsPeerSrc.Host = srcInfo.HostIp
	flowMetricsPeerSrc.SubnetID = srcInfo.SubnetId
	flowMetricsPeerDst.EpcID = dstInfo.L2EpcId
	flowMetricsPeerDst.DeviceType = DeviceType(dstInfo.L2DeviceType)
	flowMetricsPeerDst.DeviceID = dstInfo.L2DeviceId
	flowMetricsPeerDst.IsL2End = dstInfo.L2End
	flowMetricsPeerDst.IsL3End = dstInfo.L3End
	flowMetricsPeerDst.L3EpcID = dstInfo.L3EpcId
	flowMetricsPeerDst.L3DeviceType = DeviceType(dstInfo.L3DeviceType)
	flowMetricsPeerDst.L3DeviceID = dstInfo.L3DeviceId
	flowMetricsPeerDst.Host = dstInfo.HostIp
	flowMetricsPeerDst.SubnetID = dstInfo.SubnetId
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

func (m *FlowMap) checkIfDoFlowPerf(flowExtra *FlowExtra) bool {
	if flowExtra.taggedFlow.PolicyData != nil && flowExtra.taggedFlow.PolicyData.ActionFlags&FLOW_PERF_ACTION_FLAGS != 0 {
		if flowExtra.metaFlowPerf == nil {
			flowExtra.metaFlowPerf = AcquireMetaFlowPerf()
		}
		return true
	}

	return false
}

// hash of the key L3, symmetric
func getKeyL3Hash(meta *MetaPacket, basis uint32) uint64 {
	ipSrc := uint64(meta.IpSrc)
	ipDst := uint64(meta.IpDst)
	if meta.EthType == layers.EthernetTypeIPv6 {
		ipSrc = uint64(GetIpHash(meta.Ip6Src))
		ipDst = uint64(GetIpHash(meta.Ip6Dst))
	}
	if ipSrc >= ipDst {
		return ipSrc<<32 | ipDst
	}
	return ipDst<<32 | ipSrc
}

// hash of the key L4, symmetric
func getKeyL4Hash(meta *MetaPacket, basis uint32) uint64 {
	portSrc := uint32(meta.PortSrc)
	portDst := uint32(meta.PortDst)
	if portSrc >= portDst {
		return uint64(hashAdd(basis, (portSrc<<16)|portDst))
	}
	return uint64(hashAdd(basis, (portDst<<16)|portSrc))
}

func (m *FlowMap) getQuinTupleHash(meta *MetaPacket) uint64 {
	return getKeyL3Hash(meta, m.hashBasis) ^ ((uint64(meta.InPort) << 32) | getKeyL4Hash(meta, m.hashBasis))
}

func (m *FlowMap) getEthOthersQuinTupleHash(meta *MetaPacket) uint64 {
	return meta.MacSrc ^ meta.MacDst
}
