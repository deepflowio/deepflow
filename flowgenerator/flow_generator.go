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
	. "gitlab.x.lan/yunshan/droplet-libs/stats"
)

var log = logging.MustGetLogger("flowgenerator")

// hash of the key L3, symmetric
func getKeyL3Hash(meta *MetaPacket, basis uint32) uint64 {
	return uint64(hashAdd(basis, meta.IpSrc^meta.IpDst))
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

func isFromTor(inPort uint32) bool {
	return inPort&PACKET_SOURCE_TOR == PACKET_SOURCE_TOR
}

func MacEquals(meta *MetaPacket, flowMacSrc, flowMacDst MacInt) bool {
	if flowMacSrc == meta.MacSrc && flowMacDst == meta.MacDst {
		return true
	}
	if flowMacSrc == meta.MacDst && flowMacDst == meta.MacSrc {
		return true
	}
	return false
}

func (f *FlowExtra) TunnelMatch(metaTunnelInfo, flowTunnelInfo *TunnelInfo) bool {
	if metaTunnelInfo == nil {
		metaTunnelInfo = &TunnelInfo{}
	}
	if flowTunnelInfo.Id == 0 && metaTunnelInfo.Id == 0 {
		return true
	}
	if flowTunnelInfo.Id != metaTunnelInfo.Id || flowTunnelInfo.Type != metaTunnelInfo.Type {
		return false
	}
	return flowTunnelInfo.Src^metaTunnelInfo.Src^flowTunnelInfo.Dst^metaTunnelInfo.Dst == 0
}

func (f *FlowCache) keyMatch(meta *MetaPacket) (*FlowExtra, bool, *ElementFlowExtra) {
	for e := f.flowList.Front(); e != nil; e = e.Next() {
		flowExtra := e.Value
		taggedFlow := flowExtra.taggedFlow
		if taggedFlow.Exporter != meta.Exporter || meta.InPort != taggedFlow.InPort {
			continue
		}
		if isFromTor(meta.InPort) && !MacEquals(meta, taggedFlow.MACSrc, taggedFlow.MACDst) {
			continue
		}
		if taggedFlow.Proto != meta.Protocol ||
			!flowExtra.TunnelMatch(meta.Tunnel, &taggedFlow.TunnelInfo) {
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
	taggedFlow.TimeBitmap = 1
	taggedFlow.StartTime = now
	taggedFlow.EndTime = now
	taggedFlow.CurStartTime = now
	taggedFlow.VLAN = meta.Vlan
	taggedFlow.EthType = meta.EthType
	taggedFlow.PolicyData = meta.PolicyData

	flowExtra := AcquireFlowExtra()
	flowExtra.taggedFlow = taggedFlow
	flowExtra.flowState = FLOW_STATE_RAW
	flowExtra.recentTime = now
	flowExtra.reversed = false
	flowExtra.circlePktGot = true

	return flowExtra
}

func (f *FlowGenerator) updateFlowStateMachine(flowExtra *FlowExtra, flags uint8, reply, invalid bool) bool {
	taggedFlow := flowExtra.taggedFlow
	if reply {
		taggedFlow.FlowMetricsPeerDst.TCPFlags |= flags
	} else {
		taggedFlow.FlowMetricsPeerSrc.TCPFlags |= flags
	}
	if isExceptionFlags(flags, reply) || invalid {
		flowExtra.timeout = f.TimeoutConfig.Exception
		flowExtra.flowState = FLOW_STATE_EXCEPTION
		return false
	}
	var timeout time.Duration
	var flowState FlowState
	closed := false
	if stateValue, ok := f.stateMachineMaster[flowExtra.flowState][flags&TCP_FLAG_MASK]; ok {
		timeout = stateValue.timeout
		flowState = stateValue.flowState
		closed = stateValue.closed
	} else {
		timeout = f.TimeoutConfig.Exception
		flowState = FLOW_STATE_EXCEPTION
		closed = false
	}
	if reply {
		if stateValue, ok := f.stateMachineSlave[flowExtra.flowState][flags&TCP_FLAG_MASK]; ok {
			timeout = stateValue.timeout
			flowState = stateValue.flowState
			closed = stateValue.closed
		}
	}
	flowExtra.flowState = flowState
	if taggedFlow.FlowMetricsPeerSrc.TotalPacketCount == 0 || taggedFlow.FlowMetricsPeerDst.TotalPacketCount == 0 {
		flowExtra.timeout = f.SingleDirection
	} else {
		flowExtra.timeout = timeout
	}
	return closed
}

func updatePlatformData(taggedFlow *TaggedFlow, endpointData *EndpointData, reply bool) {
	if endpointData == nil {
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
	if srcInfo != nil {
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
		taggedFlow.GroupIDs0 = srcInfo.GroupIds
	}
	if dstInfo != nil {
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
		taggedFlow.GroupIDs1 = dstInfo.GroupIds
	}
}

func reversePolicyData(policyData *PolicyData) {
	if policyData == nil {
		return
	}
	for i, aclAction := range policyData.AclActions {
		policyData.AclActions[i] = aclAction.ReverseDirection()
	}
}

func (f *FlowExtra) reverseFlow() {
	taggedFlow := f.taggedFlow
	taggedFlow.TunnelInfo.Src, taggedFlow.TunnelInfo.Dst = taggedFlow.TunnelInfo.Dst, taggedFlow.TunnelInfo.Src
	taggedFlow.MACSrc, taggedFlow.MACDst = taggedFlow.MACDst, taggedFlow.MACSrc
	taggedFlow.IPSrc, taggedFlow.IPDst = taggedFlow.IPDst, taggedFlow.IPSrc
	taggedFlow.PortSrc, taggedFlow.PortDst = taggedFlow.PortDst, taggedFlow.PortSrc
	taggedFlow.FlowMetricsPeerSrc, taggedFlow.FlowMetricsPeerDst = FlowMetricsPeerSrc(taggedFlow.FlowMetricsPeerDst), FlowMetricsPeerDst(taggedFlow.FlowMetricsPeerSrc)
	taggedFlow.GroupIDs0, taggedFlow.GroupIDs1 = taggedFlow.GroupIDs1, taggedFlow.GroupIDs0
	reversePolicyData(taggedFlow.PolicyData)
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
		taggedFlow.CurStartTime = packetTimestamp
		taggedFlow.PolicyData = meta.PolicyData
		if flowExtra.reversed {
			reversePolicyData(taggedFlow.PolicyData)
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
	taggedFlow.TimeBitmap |= 1 << uint64((packetTimestamp-startTime)/time.Second)
}

func (f *FlowExtra) setCurFlowInfo(now time.Duration, desireInterval time.Duration) {
	taggedFlow := f.taggedFlow
	// desireInterval should not be too small
	if now-taggedFlow.StartTime > desireInterval+REPORT_TOLERANCE {
		taggedFlow.EndTime = now - REPORT_TOLERANCE
	} else {
		taggedFlow.EndTime = now
	}
	minArrTime := timeMin(taggedFlow.FlowMetricsPeerSrc.ArrTime0, taggedFlow.FlowMetricsPeerDst.ArrTime0)
	if minArrTime == 0 {
		minArrTime = timeMax(taggedFlow.FlowMetricsPeerSrc.ArrTime0, taggedFlow.FlowMetricsPeerDst.ArrTime0)
	}
	taggedFlow.Duration = f.recentTime - minArrTime
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

func (f *FlowGenerator) cleanHashMapByForce(hashMap []*FlowCache, start, end uint64) {
	now := time.Duration(time.Now().UnixNano())
	flowOutQueue := f.flowOutQueue
	forceReportInterval := f.forceReportInterval
	for _, flowCache := range hashMap[start:end] {
		if flowCache == nil {
			continue
		}
		flowCache.Lock()
		for e := flowCache.flowList.Front(); e != nil; {
			flowExtra := e.Value
			taggedFlow := flowExtra.taggedFlow
			atomic.AddInt32(&f.stats.CurrNumFlows, -1)
			taggedFlow.TcpPerfStats = Report(flowExtra.metaFlowPerf, false, &f.perfCounter)
			flowExtra.setCurFlowInfo(now, forceReportInterval)
			calcCloseType(taggedFlow, flowExtra.flowState)
			flowOutQueue.Put(taggedFlow)
			e = e.Next()
		}
		flowCache.flowList.Init()
		flowCache.Unlock()
	}
}

func (f *FlowGenerator) cleanTimeoutHashMap(hashMap []*FlowCache, start, end, index uint64) {
	flowOutQueue := f.flowOutQueue
	forceReportInterval := f.forceReportInterval
	sleepDuration := f.minLoopInterval
	f.cleanWaitGroup.Add(1)

loop:
	time.Sleep(sleepDuration)
	flowOutBuffer := [FLOW_OUT_BUFFER_CAP]interface{}{}
	flowOutNum := 0
	now := time.Duration(time.Now().UnixNano())
	cleanRange := now - f.minLoopInterval
	maxFlowCacheLen := 0
	nonEmptyFlowCacheNum := 0
	for _, flowCache := range hashMap[start:end] {
		flowList := flowCache.flowList
		len := flowList.Len()
		if len > 0 {
			nonEmptyFlowCacheNum++
		} else {
			continue
		}
		if maxFlowCacheLen <= len {
			maxFlowCacheLen = len
		}
		flowCache.Lock()
		e := flowList.Back()
		for e != nil {
			flowExtra := e.Value
			if flowExtra.recentTime < cleanRange && flowExtra.recentTime+flowExtra.timeout <= now {
				taggedFlow := flowExtra.taggedFlow
				atomic.AddInt32(&f.stats.CurrNumFlows, -1)
				flowExtra.setCurFlowInfo(now, forceReportInterval)
				if f.servicePortDescriptor.judgeServiceDirection(taggedFlow, flowExtra.reversed) {
					flowExtra.reverseFlow()
					flowExtra.reversed = !flowExtra.reversed
				}
				calcCloseType(taggedFlow, flowExtra.flowState)
				taggedFlow.TcpPerfStats = Report(flowExtra.metaFlowPerf, flowExtra.reversed, &f.perfCounter)
				ReleaseFlowExtra(flowExtra)
				flowOutBuffer[flowOutNum] = taggedFlow
				flowOutNum++
				if flowOutNum >= FLOW_OUT_BUFFER_CAP {
					flowOutQueue.Put(flowOutBuffer[:flowOutNum]...)
					flowOutNum = 0
				}
				del := e
				e = e.Prev()
				flowList.Remove(del)
				continue
			} else if flowExtra.taggedFlow.StartTime+forceReportInterval < now {
				taggedFlow := flowExtra.taggedFlow
				flowExtra.setCurFlowInfo(now, forceReportInterval)
				if f.servicePortDescriptor.judgeServiceDirection(taggedFlow, flowExtra.reversed) {
					flowExtra.reverseFlow()
					flowExtra.reversed = !flowExtra.reversed
				}
				taggedFlow.CloseType = CloseTypeForcedReport
				taggedFlow.TcpPerfStats = Report(flowExtra.metaFlowPerf, flowExtra.reversed, &f.perfCounter)
				flowOutBuffer[flowOutNum] = CloneTaggedFlow(taggedFlow)
				flowOutNum++
				if flowOutNum >= FLOW_OUT_BUFFER_CAP {
					flowOutQueue.Put(flowOutBuffer[:flowOutNum]...)
					flowOutNum = 0
				}
				flowExtra.resetCurFlowInfo(now)
			}
			e = e.Prev()
		}
		flowCache.Unlock()
	}
	if flowOutNum > 0 {
		flowOutQueue.Put(flowOutBuffer[:flowOutNum]...)
		flowOutNum = 0
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
			go f.cleanTimeoutHashMap(f.hashMap, start, end, i)
			log.Infof("clean goroutine %d (hashmap range %d to %d) created", i, start, end)
		} else {
			go f.cleanTimeoutHashMap(f.hashMap, start, f.mapSize, i)
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
func New(metaPacketHeaderInQueue MultiQueueReader, flowOutQueue QueueWriter, cfg FlowGeneratorConfig, index int) *FlowGenerator {
	timeoutCleanerCount = cfg.TimeoutCleanerCount
	hashMapSize = cfg.HashMapSize
	flowGenerator := &FlowGenerator{
		TimeoutConfig:           defaultTimeoutConfig,
		FlowCacheHashMap:        FlowCacheHashMap{make([]*FlowCache, hashMapSize), rand.Uint32(), hashMapSize, timeoutCleanerCount},
		metaPacketHeaderInQueue: metaPacketHeaderInQueue,
		flowOutQueue:            flowOutQueue,
		stats:                   FlowGeneratorStats{cleanRoutineFlowCacheNums: make([]int, timeoutCleanerCount), cleanRoutineMaxFlowCacheLens: make([]int, timeoutCleanerCount)},
		stateMachineMaster:      make([]map[uint8]*StateValue, FLOW_STATE_EXCEPTION+1),
		stateMachineSlave:       make([]map[uint8]*StateValue, FLOW_STATE_EXCEPTION+1),
		packetHandler:           &PacketHandler{recvBuffer: make([]interface{}, cfg.BufferSize), processBuffer: make([]interface{}, cfg.BufferSize)},
		servicePortDescriptor:   getServiceDescriptorWithIANA(),
		forceReportInterval:     cfg.ForceReportInterval,
		minLoopInterval:         defaultTimeoutConfig.minTimeout(),
		flowLimitNum:            cfg.FlowLimitNum,
		handleRunning:           false,
		cleanRunning:            false,
		index:                   index,
		perfCounter:             NewFlowPerfCounter(),
	}
	flowGenerator.initFlowCache()
	flowGenerator.initStateMachineMaster()
	flowGenerator.initStateMachineSlave()
	tags := OptionStatTags{"index": strconv.Itoa(index)}
	RegisterCountable("flow_generator", flowGenerator, tags)
	RegisterCountable(FP_NAME, &flowGenerator.perfCounter, tags)
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
