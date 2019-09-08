package flowgenerator

import (
	"math/rand"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
)

var log = logging.MustGetLogger("flowgenerator")

// hash of the key L3, symmetric
func getKeyL3Hash(meta *MetaPacket, basis uint32) uint64 {
	ipSrc := uint64(meta.IpSrc)
	ipDst := uint64(meta.IpDst)
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

func (f *FlowGenerator) getQuinTupleHash(meta *MetaPacket) uint64 {
	return getKeyL3Hash(meta, f.hashBasis) ^ ((uint64(meta.InPort) << 32) | getKeyL4Hash(meta, f.hashBasis))
}

func isFromISP(inPort uint32) bool {
	return inPort&PACKET_SOURCE_ISP == PACKET_SOURCE_ISP
}

func isFromTrident(inPort uint32) bool {
	return inPort > PACKET_SOURCE_TOR
}

func isFromTorMirror(inPort uint32) bool {
	return inPort == PACKET_SOURCE_TOR
}

// return value stands different match type, defined by MAC_MATCH_*
// TODO: maybe should consider L2End0 and L2End1 when InPort == 0x30000
func requireMacMatch(meta *MetaPacket, ignoreTorMac, ignoreL2End bool) int {
	inPort := meta.InPort
	if !ignoreL2End && isFromTrident(inPort) {
		if !meta.L2End0 && !meta.L2End1 {
			return MAC_MATCH_NONE
		} else if !meta.L2End0 {
			return MAC_MATCH_DST
		} else {
			return MAC_MATCH_SRC
		}
	}
	// for inport 0x1xxxx return MAC_MATCH_NONE
	if isFromISP(inPort) || (ignoreTorMac && isFromTorMirror(inPort)) {
		return MAC_MATCH_NONE
	}
	return MAC_MATCH_ALL
}

func MacMatch(meta *MetaPacket, flowMacSrc, flowMacDst MacInt, matchType int) bool {
	if matchType == MAC_MATCH_DST {
		return flowMacDst == meta.MacDst || flowMacSrc == meta.MacDst
	} else if matchType == MAC_MATCH_SRC {
		return flowMacSrc == meta.MacSrc || flowMacDst == meta.MacSrc
	} else {
		if flowMacSrc == meta.MacSrc && flowMacDst == meta.MacDst {
			return true
		}
		if flowMacSrc == meta.MacDst && flowMacDst == meta.MacSrc {
			return true
		}
	}
	return false
}

func (f *FlowExtra) TunnelMatch(metaTunnelInfo, flowTunnelInfo *TunnelInfo) bool {
	if flowTunnelInfo.Id == 0 && (metaTunnelInfo == nil || metaTunnelInfo.Id == 0) {
		return true
	}
	if metaTunnelInfo == nil {
		return false
	}
	if flowTunnelInfo.Id != metaTunnelInfo.Id || flowTunnelInfo.Type != metaTunnelInfo.Type {
		return false
	}
	if (flowTunnelInfo.Src == metaTunnelInfo.Src && flowTunnelInfo.Dst == metaTunnelInfo.Dst) ||
		(flowTunnelInfo.Src == metaTunnelInfo.Dst && flowTunnelInfo.Dst == metaTunnelInfo.Src) {
		return true
	}
	return false
}

func (e *FlowExtra) Match(meta *MetaPacket) bool { // FIXME: 函数定义移动到flow_extra.go，目前方便Review
	if meta.EthType != layers.EthernetTypeIPv4 { // FIXME: 支持IPv6
		return e.keyMatchForNonIp(meta)
	}

	if true { // FIXME: 去掉，目前只为方便Review
		taggedFlow := e.taggedFlow
		if taggedFlow.Exporter != meta.Exporter || meta.InPort != taggedFlow.InPort {
			return false
		}
		macMatchType := requireMacMatch(meta, ignoreTorMac, ignoreL2End)
		if macMatchType != MAC_MATCH_NONE && !MacMatch(meta, taggedFlow.MACSrc, taggedFlow.MACDst, macMatchType) {
			return false
		}
		if taggedFlow.Proto != meta.Protocol || !e.TunnelMatch(meta.Tunnel, &taggedFlow.TunnelInfo) {
			return false
		}
		flowIPSrc, flowIPDst := taggedFlow.IPSrc, taggedFlow.IPDst
		metaIpSrc, metaIpDst := meta.IpSrc, meta.IpDst
		flowPortSrc, flowPortDst := taggedFlow.PortSrc, taggedFlow.PortDst
		metaPortSrc, metaPortDst := meta.PortSrc, meta.PortDst
		if flowIPSrc == metaIpSrc && flowIPDst == metaIpDst && flowPortSrc == metaPortSrc && flowPortDst == metaPortDst {
			meta.Direction = CLIENT_TO_SERVER
			return true
		} else if flowIPSrc == metaIpDst && flowIPDst == metaIpSrc && flowPortSrc == metaPortDst && flowPortDst == metaPortSrc {
			meta.Direction = SERVER_TO_CLIENT
			return true
		}
	}
	return false
}

func (m *FlowMap) genFlowId(timestamp uint64) uint64 { // FIXME: 移动位置
	return ((uint64(m.id) & THREAD_FLOW_ID_MASK) << 32) | ((timestamp & TIMER_FLOW_ID_MASK) << 32) | (m.totalFlow & COUNTER_FLOW_ID_MASK)
}

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

func (m *FlowMap) updateFlowStateMachine(flowExtra *FlowExtra, flags uint8, serverToClient bool) bool {
	taggedFlow := flowExtra.taggedFlow
	var timeout time.Duration
	var flowState FlowState
	closed := false
	if stateValue, ok := m.stateMachineMaster[flowExtra.flowState][flags]; ok {
		timeout = stateValue.timeout
		flowState = stateValue.flowState
		closed = stateValue.closed
	} else {
		timeout = exceptionTimeout
		flowState = FLOW_STATE_EXCEPTION
		closed = false
	}
	if serverToClient { // 若flags对应的包是 服务端->客户端 时，还需要走一下Slave状态机
		if stateValue, ok := m.stateMachineSlave[flowExtra.flowState][flags]; ok {
			timeout = stateValue.timeout
			flowState = stateValue.flowState
			closed = stateValue.closed
		}
	}
	flowExtra.flowState = flowState
	if taggedFlow.FlowMetricsPeerSrc.TotalPacketCount == 0 || taggedFlow.FlowMetricsPeerDst.TotalPacketCount == 0 {
		flowExtra.timeout = singleDirectionTimeout
	} else {
		flowExtra.timeout = timeout
	}
	return closed
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

func (f *FlowExtra) setMetaPacketActiveService(meta *MetaPacket) {
	meta.IsActiveService = f.taggedFlow.Flow.IsActiveService
}

func (f *FlowExtra) reverseFlow() {
	taggedFlow := f.taggedFlow
	taggedFlow.TunnelInfo.Src, taggedFlow.TunnelInfo.Dst = taggedFlow.TunnelInfo.Dst, taggedFlow.TunnelInfo.Src
	taggedFlow.MACSrc, taggedFlow.MACDst = taggedFlow.MACDst, taggedFlow.MACSrc
	taggedFlow.IPSrc, taggedFlow.IPDst = taggedFlow.IPDst, taggedFlow.IPSrc
	taggedFlow.PortSrc, taggedFlow.PortDst = taggedFlow.PortDst, taggedFlow.PortSrc
	taggedFlow.FlowMetricsPeerSrc, taggedFlow.FlowMetricsPeerDst = FlowMetricsPeerSrc(taggedFlow.FlowMetricsPeerDst), FlowMetricsPeerDst(taggedFlow.FlowMetricsPeerSrc)
	taggedFlow.GeoEnd ^= 1 // reverse GeoEnd (0: src, 1: dst, others: N/A)
	reverseFlowTag(taggedFlow)
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

func (f *FlowExtra) setEndTimeAndDuration(timestamp time.Duration) {
	taggedFlow := f.taggedFlow
	taggedFlow.EndTime = timestamp
	taggedFlow.Duration = f.recentTime - f.minArrTime // Duration仅使用包的时间计算，不包括超时时间
	f.reported = true
}

func (f *FlowExtra) resetPacketStatInfo() {
	f.packetInTick = false
	taggedFlow := f.taggedFlow
	taggedFlow.PacketStatTime = 0
	taggedFlow.FlowMetricsPeerSrc.TickPacketCount = 0
	taggedFlow.FlowMetricsPeerDst.TickPacketCount = 0
	taggedFlow.FlowMetricsPeerSrc.TickByteCount = 0
	taggedFlow.FlowMetricsPeerDst.TickByteCount = 0
}

func (f *FlowExtra) resetFlowStatInfo(now time.Duration) {
	f.packetInCycle = false
	taggedFlow := f.taggedFlow
	taggedFlow.TimeBitmap = 0
	taggedFlow.StartTime = now
	taggedFlow.EndTime = now
	taggedFlow.FlowMetricsPeerSrc.PacketCount = 0
	taggedFlow.FlowMetricsPeerDst.PacketCount = 0
	taggedFlow.FlowMetricsPeerSrc.ByteCount = 0
	taggedFlow.FlowMetricsPeerDst.ByteCount = 0
}

func calcCloseType(taggedFlow *TaggedFlow, flowState FlowState) {
	switch flowState {
	case FLOW_STATE_EXCEPTION:
		taggedFlow.CloseType = CloseTypeUnknown
	case FLOW_STATE_OPENING_1:
		taggedFlow.CloseType = CloseTypeServerHalfOpen
	case FLOW_STATE_OPENING_2:
		taggedFlow.CloseType = CloseTypeClientHalfOpen
	case FLOW_STATE_ESTABLISHED:
		taggedFlow.CloseType = CloseTypeTimeout
	case FLOW_STATE_CLOSING_TX1:
		taggedFlow.CloseType = CloseTypeServerHalfClose
	case FLOW_STATE_CLOSING_RX1:
		taggedFlow.CloseType = CloseTypeClientHalfClose
	case FLOW_STATE_CLOSING_TX2:
		fallthrough
	case FLOW_STATE_CLOSING_RX2:
		fallthrough
	case FLOW_STATE_CLOSED:
		taggedFlow.CloseType = CloseTypeTCPFin
	case FLOW_STATE_RESET:
		if flagContain(taggedFlow.FlowMetricsPeerDst.TCPFlags, TCP_RST) {
			taggedFlow.CloseType = CloseTypeTCPServerRst
		} else {
			taggedFlow.CloseType = CloseTypeTCPClientRst
		}
	default:
		log.Warningf("unexcepted 'unknown' close type, flow id is %d", taggedFlow.FlowID)
		taggedFlow.CloseType = CloseTypeUnknown
	}
}

func (f *FlowGenerator) processPackets(processBuffer []interface{}) {
	for i, e := range processBuffer {
		if e == nil { // flush indicator
			f.flowMap.InjectFlushTicker(toTimestamp(time.Now()))
			continue
		}

		meta := e.(*MetaPacket)

		if meta.EthType == layers.EthernetTypeIPv6 { // FIXME: 当前版本Flow和Metering都不需要IPv6, 直接返回
			ReleaseMetaPacket(meta)
			processBuffer[i] = nil
			continue
		}

		hash := uint64(0)
		if meta.EthType != layers.EthernetTypeIPv4 { // FIXME: 支持IPv6
			hash = f.getNonIpQuinTupleHash(meta)
		} else {
			hash = f.getQuinTupleHash(meta)
		}
		f.flowMap.InjectMetaPacket(hash, meta)

		ReleaseMetaPacket(meta)
		processBuffer[i] = nil
	}
}

func (f *FlowGenerator) handlePackets() {
	inputQueue := f.inputQueue
	recvBuffer := make([]interface{}, QUEUE_BATCH_SIZE)
	gotSize := 0

	for f.running {
		gotSize = inputQueue.Gets(recvBuffer)
		f.processPackets(recvBuffer[:gotSize])
	}
}

func (f *FlowGenerator) Start() {
	if !f.running {
		f.running = true
		go f.handlePackets()
	}
	log.Infof("flow generator %d started", f.index)
}

func (f *FlowGenerator) Stop() {
	if f.running {
		f.running = false
	}
	log.Infof("flow generator %d stopped", f.index)
}

// create a new flow generator
func New(inputQueue QueueReader, packetAppQueue, flowAppQueue QueueWriter, flowLimitNum, index int, flushInterval time.Duration) *FlowGenerator {
	flowGenerator := &FlowGenerator{
		hashBasis:  rand.Uint32(),
		flowMap:    NewFlowMap(int(hashMapSize), flowLimitNum, index, maxTimeout, reportTolerance, flushInterval, packetAppQueue, flowAppQueue),
		inputQueue: inputQueue,
		index:      index,
	}
	return flowGenerator
}

func (f *FlowMap) checkIfDoFlowPerf(flowExtra *FlowExtra) bool { // FIXME: 移动到flow_map.go
	if flowExtra.taggedFlow.PolicyData != nil &&
		flowExtra.taggedFlow.PolicyData.ActionFlags&FLOW_PERF_ACTION_FLAGS != 0 {
		if flowExtra.metaFlowPerf == nil {
			flowExtra.metaFlowPerf = AcquireMetaFlowPerf()
		}
		return true
	}

	return false
}
