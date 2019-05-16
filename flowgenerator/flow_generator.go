package flowgenerator

import (
	"math/rand"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
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

func (f *FlowGenerator) TunnelMatch(metaTunnelInfo, flowTunnelInfo *TunnelInfo) bool {
	if metaTunnelInfo == nil {
		metaTunnelInfo = f.innerTunnelInfo
	}
	if flowTunnelInfo.Id == 0 && metaTunnelInfo.Id == 0 {
		return true
	}
	if flowTunnelInfo.Id != metaTunnelInfo.Id || flowTunnelInfo.Type != metaTunnelInfo.Type {
		return false
	}
	// FIXME: should compare with outer ip at the same time
	if (flowTunnelInfo.Src == metaTunnelInfo.Src && flowTunnelInfo.Dst == metaTunnelInfo.Dst) ||
		(flowTunnelInfo.Src == metaTunnelInfo.Dst && flowTunnelInfo.Dst == metaTunnelInfo.Src) {
		return true
	}
	return false
}

func (f *FlowGenerator) keyMatch(flowCache *FlowCache, meta *MetaPacket) (*FlowExtra, bool, *ElementFlowExtra) {
	for e := flowCache.flowList.Front(); e != nil; e = e.Next() {
		flowExtra := e.Value
		taggedFlow := flowExtra.taggedFlow
		if taggedFlow.Exporter != meta.Exporter || meta.InPort != taggedFlow.InPort {
			continue
		}
		macMatchType := requireMacMatch(meta, ignoreTorMac, ignoreL2End)
		if macMatchType != MAC_MATCH_NONE && !MacMatch(meta, taggedFlow.MACSrc, taggedFlow.MACDst, macMatchType) {
			continue
		}
		if taggedFlow.Proto != meta.Protocol ||
			!f.TunnelMatch(meta.Tunnel, &taggedFlow.TunnelInfo) {
			continue
		}
		flowIPSrc, flowIPDst := taggedFlow.IPSrc, taggedFlow.IPDst
		metaIpSrc, metaIpDst := meta.IpSrc, meta.IpDst
		flowPortSrc, flowPortDst := taggedFlow.PortSrc, taggedFlow.PortDst
		metaPortSrc, metaPortDst := meta.PortSrc, meta.PortDst
		if flowIPSrc == metaIpSrc && flowIPDst == metaIpDst && flowPortSrc == metaPortSrc && flowPortDst == metaPortDst {
			return flowExtra, false, e
		} else if flowIPSrc == metaIpDst && flowIPDst == metaIpSrc && flowPortSrc == metaPortDst && flowPortDst == metaPortSrc {
			return flowExtra, true, e
		}
	}
	return nil, false, nil
}

func (f *FlowGenerator) initFlowCache() bool {
	if f.hashMap == nil {
		log.Error("flow cache init failed: FlowGenerator.hashMap is nil")
		return false
	}
	for i := range f.hashMap {
		f.hashMap[i] = &FlowCache{capacity: FLOW_CACHE_CAP, flowList: NewListFlowExtra()}
	}
	return true
}

func (f *FlowGenerator) addFlow(flowCache *FlowCache, flowExtra *FlowExtra) {
	flowCache.flowList.PushFront(flowExtra)
}

func (f *FlowGenerator) genFlowId(timestamp uint64, inPort uint64) uint64 {
	return ((inPort & IN_PORT_FLOW_ID_MASK) << 32) | ((timestamp & TIMER_FLOW_ID_MASK) << 32) | (f.stats.TotalNumFlows & TOTAL_FLOWS_ID_MASK)
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

func (f *FlowGenerator) initFlow(meta *MetaPacket, now time.Duration) *FlowExtra {
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
	taggedFlow.FlowID = f.genFlowId(uint64(now), uint64(meta.InPort))
	taggedFlow.TimeBitmap = getBitmap(now)
	taggedFlow.StartTime = now
	taggedFlow.EndTime = now
	taggedFlow.CurStartTime = now
	taggedFlow.VLAN = meta.Vlan
	taggedFlow.EthType = meta.EthType
	taggedFlow.Hash = meta.Hash
	updateFlowTag(taggedFlow, meta)

	flowExtra := AcquireFlowExtra()
	flowExtra.taggedFlow = taggedFlow
	flowExtra.flowState = FLOW_STATE_RAW
	flowExtra.minArrTime = now
	flowExtra.recentTime = now
	flowExtra.reported = false
	flowExtra.reversed = false
	flowExtra.circlePktGot = true

	return flowExtra
}

func (f *FlowGenerator) updateFlowStateMachine(flowExtra *FlowExtra, flags uint8, reply bool) bool {
	taggedFlow := flowExtra.taggedFlow
	var timeout time.Duration
	var flowState FlowState
	closed := false
	if stateValue, ok := f.stateMachineMaster[flowExtra.flowState][flags]; ok {
		timeout = stateValue.timeout
		flowState = stateValue.flowState
		closed = stateValue.closed
	} else {
		timeout = exceptionTimeout
		flowState = FLOW_STATE_EXCEPTION
		closed = false
	}
	if reply {
		if stateValue, ok := f.stateMachineSlave[flowExtra.flowState][flags]; ok {
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

func updatePlatformData(taggedFlow *TaggedFlow, endpointData *EndpointData, reply bool) {
	if endpointData == nil {
		log.Warning("Unexpected nil packet endpointData")
		return
	}
	var srcInfo, dstInfo *EndpointInfo
	if reply {
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

func (f *FlowGenerator) tryReverseFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) bool {
	if flowExtra.reversed || meta.TcpData == nil {
		return false
	}
	// if meta.Invalid is false, TcpData will not be nil
	if flagEqual(meta.TcpData.Flags&TCP_FLAG_MASK, TCP_SYN|TCP_ACK) && !reply {
		flowExtra.reverseFlow()
		flowExtra.reversed = !flowExtra.reversed
		return true
	}
	return false
}

func (f *FlowGenerator) updateFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) {
	taggedFlow := flowExtra.taggedFlow
	bytes := uint64(meta.PacketLen)
	packetTimestamp := meta.Timestamp
	startTime := taggedFlow.StartTime
	if packetTimestamp < flowExtra.recentTime || packetTimestamp < startTime {
		packetTimestamp = timeMax(flowExtra.recentTime, startTime)
	}
	flowExtra.recentTime = packetTimestamp
	if !flowExtra.circlePktGot {
		flowExtra.circlePktGot = true
		// FIXME: if StartTime is fixed, CurStartTime should be recalculated?
		taggedFlow.CurStartTime = packetTimestamp
		updateFlowTag(taggedFlow, meta)
		if reply {
			reverseFlowTag(taggedFlow)
		}
		updatePlatformData(taggedFlow, meta.EndpointData, reply)
	}
	if reply {
		if taggedFlow.FlowMetricsPeerDst.TotalPacketCount == 0 {
			taggedFlow.FlowMetricsPeerDst.ArrTime0 = packetTimestamp
		}
		taggedFlow.FlowMetricsPeerDst.ArrTimeLast = packetTimestamp
		taggedFlow.FlowMetricsPeerDst.PacketCount++
		taggedFlow.FlowMetricsPeerDst.TotalPacketCount++
		taggedFlow.FlowMetricsPeerDst.ByteCount += bytes
		taggedFlow.FlowMetricsPeerDst.TotalByteCount += bytes
	} else {
		if taggedFlow.FlowMetricsPeerSrc.TotalPacketCount == 0 {
			taggedFlow.FlowMetricsPeerSrc.ArrTime0 = packetTimestamp
		}
		taggedFlow.FlowMetricsPeerSrc.ArrTimeLast = packetTimestamp
		taggedFlow.FlowMetricsPeerSrc.PacketCount++
		taggedFlow.FlowMetricsPeerSrc.TotalPacketCount++
		taggedFlow.FlowMetricsPeerSrc.ByteCount += bytes
		taggedFlow.FlowMetricsPeerSrc.TotalByteCount += bytes
	}
	// a flow will report every minute and StartTime will be reset, so the value could not be overflow
	taggedFlow.TimeBitmap |= getBitmap(packetTimestamp)
}

func (f *FlowExtra) setCurFlowInfo(now time.Duration, desireInterval, reportTolerance time.Duration) {
	taggedFlow := f.taggedFlow
	// desireInterval should not be too small
	if now-taggedFlow.StartTime > desireInterval+reportTolerance {
		taggedFlow.EndTime = now - reportTolerance
	} else {
		taggedFlow.EndTime = now
	}
	// FIXME bitmap should be recalculated, 5.5.2
	pivotalTime := taggedFlow.EndTime - taggedFlow.EndTime%forceReportInterval
	if taggedFlow.StartTime < pivotalTime && taggedFlow.EndTime > pivotalTime {
		taggedFlow.StartTime = pivotalTime
		if !f.reported {
			// FIXME maybe we should choose only one ArrTime
			taggedFlow.FlowMetricsPeerSrc.ArrTime0 = pivotalTime
			taggedFlow.FlowMetricsPeerDst.ArrTime0 = pivotalTime
		}
	}
	taggedFlow.Duration = f.recentTime - f.minArrTime
	f.reported = true
}

func (f *FlowExtra) resetCurFlowInfo(now time.Duration) {
	f.circlePktGot = false
	taggedFlow := f.taggedFlow
	taggedFlow.TimeBitmap = 0
	taggedFlow.StartTime = now
	taggedFlow.EndTime = now
	taggedFlow.CurStartTime = now
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
	for _, e := range processBuffer {
		meta := e.(*MetaPacket)
		if meta.Protocol == layers.IPProtocolTCP {
			f.processTcpPacket(meta)
		} else if meta.Protocol == layers.IPProtocolUDP {
			f.processUdpPacket(meta)
		} else if meta.EthType != layers.EthernetTypeIPv4 {
			f.processNonIpPacket(meta)
		} else {
			f.processOtherIpPacket(meta)
		}
		ReleaseMetaPacket(meta)
	}
	f.packetHandler.Done()
}

func (f *FlowGenerator) handlePackets() {
	metaPacketInQueue := f.metaPacketHeaderInQueue
	packetHandler := f.packetHandler
	recvBuffer := packetHandler.recvBuffer
	processBuffer := packetHandler.processBuffer
	gotSize := 0
	hashKey := HashKey(f.index)
loop:
	packetHandler.Add(1)
	go f.processPackets(processBuffer[:gotSize])
	gotSize = metaPacketInQueue.Gets(hashKey, recvBuffer)
	packetHandler.Wait()
	processBuffer, recvBuffer = recvBuffer, processBuffer
	goto loop
}

func (f *FlowGenerator) reportForClean(flowExtra *FlowExtra, force bool, now time.Duration) *TaggedFlow {
	taggedFlow := flowExtra.taggedFlow
	if f.checkL4ServiceReverse(taggedFlow, flowExtra.reversed, now) {
		flowExtra.reverseFlow()
		flowExtra.reversed = true
	}
	if taggedFlow.Proto == layers.IPProtocolTCP {
		taggedFlow.TcpPerfStats = Report(flowExtra.metaFlowPerf, flowExtra.reversed, &f.perfCounter)
	}
	if force {
		taggedFlow.CloseType = CloseTypeForcedReport
		return CloneTaggedFlow(taggedFlow)
	}
	calcCloseType(taggedFlow, flowExtra.flowState)
	ReleaseFlowExtra(flowExtra)
	return taggedFlow
}

func tryCleanBuffer(queue QueueWriter, buffer []interface{}, num int) int {
	if num >= FLOW_OUT_BUFFER_CAP {
		queue.Put(buffer[:num]...)
		return 0
	}
	return num
}

func reportFlowListTimeout(f *FlowGenerator, list *ListFlowExtra, now, cleanRange time.Duration, buffer []interface{}, num int) int {
	flowOutQueue := f.flowOutQueue
	cleanCount := 0
	e := list.Back()
	for e != nil {
		flowExtra := e.Value
		if flowExtra.recentTime < cleanRange && flowExtra.recentTime+flowExtra.timeout <= now {
			flowExtra.setCurFlowInfo(now, forceReportInterval, reportTolerance)
			buffer[num] = f.reportForClean(flowExtra, false, now)
			num = tryCleanBuffer(flowOutQueue, buffer, num+1)
			cleanCount++
			del := e
			e = e.Prev()
			list.Remove(del)
			continue
		}
		e = e.Prev()
	}
	if cleanCount > 0 {
		atomic.AddInt32(&f.stats.CurrNumFlows, int32(0-cleanCount))
	}
	return num
}

func reportFlowListGeneral(f *FlowGenerator, list *ListFlowExtra, now, cleanRange time.Duration, buffer []interface{}, num int) int {
	flowOutQueue := f.flowOutQueue
	cleanCount := 0
	e := list.Back()
	for e != nil {
		flowExtra := e.Value
		flowExtra.setCurFlowInfo(now, forceReportInterval, reportTolerance)
		if flowExtra.recentTime < cleanRange && flowExtra.recentTime+flowExtra.timeout <= now {
			buffer[num] = f.reportForClean(flowExtra, false, now)
			cleanCount++
			del := e
			e = e.Prev()
			list.Remove(del)
		} else {
			buffer[num] = f.reportForClean(flowExtra, true, now)
			flowExtra.resetCurFlowInfo(now)
			e = e.Prev()
		}
		num = tryCleanBuffer(flowOutQueue, buffer, num+1)
	}
	if cleanCount > 0 {
		atomic.AddInt32(&f.stats.CurrNumFlows, int32(0-cleanCount))
	}
	return num
}

func (f *FlowGenerator) cleanHashMapByForce(hashMap []*FlowCache, start, end uint64) {
	now := toTimestamp(time.Now())
	flowOutQueue := f.flowOutQueue
	for _, flowCache := range hashMap[start:end] {
		if flowCache == nil {
			continue
		}
		flowCache.Lock()
		for e := flowCache.flowList.Front(); e != nil; {
			flowExtra := e.Value
			flowExtra.setCurFlowInfo(now, forceReportInterval, reportTolerance)
			taggedFlow := f.reportForClean(flowExtra, false, now)
			atomic.AddInt32(&f.stats.CurrNumFlows, -1)
			flowOutQueue.Put(taggedFlow)
			e = e.Next()
		}
		flowCache.flowList.Init()
		flowCache.Unlock()
	}
}

func (f *FlowGenerator) cleanTimeoutHashMap(start, end, index uint64) {
	hashMap := f.hashMap
	// temp buffer to write flow
	flowOutBuffer := [FLOW_OUT_BUFFER_CAP]interface{}{}
	// vars about time
	sleepDuration := flowCleanInterval
	reportFlowList := reportFlowListTimeout
	now := toTimestamp(time.Now())
	nextGeneralReport := now + forceReportInterval - now%forceReportInterval
	f.cleanWaitGroup.Add(1)

loop:
	time.Sleep(sleepDuration)
	now = toTimestamp(time.Now())
	cleanRange := now - flowCleanInterval
	nonEmptyFlowCacheNum := 0
	maxFlowCacheLen := 0
	num := 0
	if now > nextGeneralReport {
		reportFlowList = reportFlowListGeneral
		nextGeneralReport += forceReportInterval
	} else {
		reportFlowList = reportFlowListTimeout
	}
	for _, flowCache := range hashMap[start:end] {
		flowList := flowCache.flowList
		length := flowList.Len()
		if length > 0 {
			nonEmptyFlowCacheNum++
		} else {
			continue
		}
		if maxFlowCacheLen <= length {
			maxFlowCacheLen = length
		}
		flowCache.Lock()
		num = reportFlowList(f, flowList, now, cleanRange, flowOutBuffer[:], num)
		flowCache.Unlock()
	}
	if num > 0 {
		f.flowOutQueue.Put(flowOutBuffer[:num]...)
	}
	// calc the next sleep duration
	endtime := toTimestamp(time.Now())
	used := endtime - now
	if flowCleanInterval > used {
		sleepDuration = flowCleanInterval - used
	} else {
		sleepDuration = 0
		log.Debugf("used: %d, clean interval: %d", used, flowCleanInterval)
		log.Debugf("clean time of generator %d is too long, maybe pressure is heavy", f.index)
	}
	f.stats.cleanRoutineFlowCacheNums[index] = nonEmptyFlowCacheNum
	f.stats.cleanRoutineMaxFlowCacheLens[index] = maxFlowCacheLen
	if f.cleanRunning {
		goto loop
	}
	f.cleanHashMapByForce(hashMap, start, end)
	f.cleanWaitGroup.Done()
}

func (f *FlowGenerator) timeoutReport() {
	var flowCacheNum uint64
	f.cleanRunning = true
	if f.mapSize%f.timeoutCleanerCount != 0 {
		flowCacheNum = f.mapSize/f.timeoutCleanerCount + 1
	} else {
		flowCacheNum = f.mapSize / f.timeoutCleanerCount
	}
	for i := uint64(0); i < f.timeoutCleanerCount; i++ {
		start := i * flowCacheNum
		end := start + flowCacheNum
		if end <= f.mapSize {
			go f.cleanTimeoutHashMap(start, end, i)
			log.Infof("clean goroutine %d (hashmap range %d to %d) created", i, start, end)
		} else {
			go f.cleanTimeoutHashMap(start, f.mapSize, i)
			log.Infof("clean goroutine %d (hashmap range %d to %d) created", i, start, f.mapSize)
			break
		}
	}
}

func (f *FlowGenerator) run() {
	if !f.cleanRunning {
		f.cleanRunning = true
		f.timeoutReport()
	}
	if !f.handleRunning {
		f.handleRunning = true
		go f.handlePackets()
	}
}

// we need these goroutines are thread safe
func (f *FlowGenerator) Start() {
	f.run()
	log.Infof("flow generator %d started", f.index)
}

func (f *FlowGenerator) Stop() {
	if f.handleRunning {
		f.handleRunning = false
	}
	if f.cleanRunning {
		f.cleanRunning = false
		f.cleanWaitGroup.Wait()
	}
	log.Infof("flow generator %d stopped", f.index)
}

// create a new flow generator
func New(metaPacketHeaderInQueue MultiQueueReader, flowOutQueue QueueWriter, bufferSize int, flowLimitNum int32, index int) *FlowGenerator {
	flowGenerator := &FlowGenerator{
		FlowCacheHashMap:        FlowCacheHashMap{make([]*FlowCache, hashMapSize), rand.Uint32(), hashMapSize, timeoutCleanerCount, &TunnelInfo{}},
		FlowGeo:                 innerFlowGeo,
		metaPacketHeaderInQueue: metaPacketHeaderInQueue,
		flowOutQueue:            flowOutQueue,
		stats:                   FlowGeneratorStats{cleanRoutineFlowCacheNums: make([]int, timeoutCleanerCount), cleanRoutineMaxFlowCacheLens: make([]int, timeoutCleanerCount)},
		stateMachineMaster:      make([]map[uint8]*StateValue, FLOW_STATE_EXCEPTION+1),
		stateMachineSlave:       make([]map[uint8]*StateValue, FLOW_STATE_EXCEPTION+1),
		packetHandler:           &PacketHandler{recvBuffer: make([]interface{}, bufferSize), processBuffer: make([]interface{}, bufferSize)},
		bufferSize:              bufferSize,
		flowLimitNum:            flowLimitNum,
		handleRunning:           false,
		cleanRunning:            false,
		index:                   index,
		perfCounter:             NewFlowPerfCounter(),
	}
	flowGenerator.initFlowCache()
	flowGenerator.initStateMachineMaster()
	flowGenerator.initStateMachineSlave()
	tags := stats.OptionStatTags{"index": strconv.Itoa(index)}
	stats.RegisterCountable("flow-generator", flowGenerator, tags)
	stats.RegisterCountable(FP_NAME, &flowGenerator.perfCounter, tags)
	log.Infof("flow generator %d created", index)
	return flowGenerator
}

func (f *FlowGenerator) checkIfDoFlowPerf(flowExtra *FlowExtra) bool {
	if flowExtra.taggedFlow.PolicyData != nil &&
		flowExtra.taggedFlow.PolicyData.ActionFlags&FLOW_PERF_ACTION_FLAGS > 0 {
		if flowExtra.metaFlowPerf == nil {
			flowExtra.metaFlowPerf = AcquireMetaFlowPerf()
		}
		return true
	}

	return false
}

func (f *FlowGenerator) checkL4ServiceReverse(taggedFlow *TaggedFlow, reversed bool, now time.Duration) bool {
	if reversed {
		return false
	}
	if taggedFlow.Proto == layers.IPProtocolTCP {
		return f.checkTcpServiceReverse(taggedFlow, reversed, now)
	} else if taggedFlow.Proto == layers.IPProtocolUDP {
		return f.checkUdpServiceReverse(taggedFlow, reversed, now)
	}
	return false
}
