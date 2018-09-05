package flowgenerator

import (
	"math/rand"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	. "gitlab.x.lan/yunshan/droplet-libs/stats"
)

var log = logging.MustGetLogger("flowgenerator")

func (f *FlowGenerator) genFlowKey(meta *MetaPacket) *FlowKey {
	flowKey := f.innerFlowKey
	flowKey.Exporter = meta.Exporter
	flowKey.MACSrc = meta.MacSrc
	flowKey.MACDst = meta.MacDst
	flowKey.IPSrc = meta.IpSrc
	flowKey.IPDst = meta.IpDst
	flowKey.Proto = meta.Protocol
	flowKey.PortSrc = meta.PortSrc
	flowKey.PortDst = meta.PortDst
	flowKey.InPort = meta.InPort
	if tunnel := meta.Tunnel; tunnel != nil {
		flowKey.TunnelInfo = *tunnel
	} else {
		flowKey.TunnelInfo.Id = 0
		flowKey.TunnelInfo.Type = 0
		flowKey.TunnelInfo.Src = 0
		flowKey.TunnelInfo.Dst = 0
	}
	return flowKey
}

// hash of the key L3, symmetric
func getKeyL3Hash(flowKey *FlowKey) uint64 {
	ipSrc := uint64(flowKey.IPSrc)
	ipDst := uint64(flowKey.IPDst)
	if ipSrc >= ipDst {
		return (ipSrc << 32) | ipDst
	}
	return ipSrc | (ipDst << 32)
}

// hash of the key L4, symmetric
func getKeyL4Hash(flowKey *FlowKey, basis uint32) uint64 {
	portSrc := uint32(flowKey.PortSrc)
	portDst := uint32(flowKey.PortDst)
	if portSrc >= portDst {
		return uint64(hashFinish(hashAdd(basis, (portSrc<<16)|portDst)))
	}
	return uint64(hashFinish(hashAdd(basis, (portDst<<16)|portSrc)))
}

func (f *FlowGenerator) getQuinTupleHash(flowKey *FlowKey) uint64 {
	return getKeyL3Hash(flowKey) ^ ((uint64(flowKey.InPort) << 32) | getKeyL4Hash(flowKey, f.hashBasis))
}

func isFromTor(inPort uint32) bool {
	return inPort&PACKET_SOURCE_TOR == PACKET_SOURCE_TOR
}

func (f *FlowExtra) MacEquals(meta *MetaPacket) bool {
	taggedFlow := f.taggedFlow
	flowMacSrc, flowMacDst := taggedFlow.MACSrc, taggedFlow.MACDst
	if flowMacSrc == meta.MacSrc && flowMacDst == meta.MacDst {
		return true
	}
	if flowMacSrc == meta.MacDst && flowMacDst == meta.MacSrc {
		return true
	}
	return false
}

func (f *FlowExtra) TunnelMatch(key *FlowKey) bool {
	taggedFlow := f.taggedFlow
	if taggedFlow.TunnelInfo.Id == 0 && key.TunnelInfo.Id == 0 {
		return true
	}
	if taggedFlow.TunnelInfo.Type != key.TunnelInfo.Type || taggedFlow.TunnelInfo.Id != key.TunnelInfo.Id {
		return false
	}
	return taggedFlow.TunnelInfo.Src^key.TunnelInfo.Src^taggedFlow.TunnelInfo.Dst^key.TunnelInfo.Dst == 0
}

func (f *FlowCache) keyMatch(meta *MetaPacket, key *FlowKey) (*FlowExtra, bool) {
	f.Lock()
	for e := f.flowList.Front(); e != nil; e = e.Next() {
		flowExtra := e.Value
		taggedFlow := flowExtra.taggedFlow
		if taggedFlow.Exporter != key.Exporter || (isFromTor(key.InPort) && !flowExtra.MacEquals(meta)) {
			continue
		}
		if taggedFlow.Proto != key.Proto || !flowExtra.TunnelMatch(key) {
			continue
		}
		if taggedFlow.IPSrc == key.IPSrc && taggedFlow.IPDst == key.IPDst && taggedFlow.PortSrc == key.PortSrc && taggedFlow.PortDst == key.PortDst {
			f.flowList.MoveToFront(e)
			f.Unlock()
			return flowExtra, false
		} else if taggedFlow.IPSrc == key.IPDst && taggedFlow.IPDst == key.IPSrc && taggedFlow.PortSrc == key.PortDst && taggedFlow.PortDst == key.PortSrc {
			f.flowList.MoveToFront(e)
			f.Unlock()
			return flowExtra, true
		}
	}
	f.Unlock()
	return nil, false
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

func (f *FlowGenerator) initFastPathPool() {
	f.FastPath.TaggedFlowPool.New = func() interface{} {
		return &TaggedFlow{}
	}
	f.FastPath.FlowExtraPool.New = func() interface{} {
		return &FlowExtra{}
	}
}

func (f *FlowGenerator) addFlow(flowCache *FlowCache, flowExtra *FlowExtra) *FlowExtra {
	if f.stats.CurrNumFlows >= f.flowLimitNum {
		return flowExtra
	}
	flowCache.Lock()
	flowCache.flowList.PushFront(flowExtra)
	flowCache.Unlock()
	return nil
}

func (f *FlowGenerator) genFlowId(timestamp uint64, inPort uint64) uint64 {
	return ((inPort & IN_PORT_FLOW_ID_MASK) << 32) | ((timestamp & TIMER_FLOW_ID_MASK) << 32) | (f.stats.TotalNumFlows & TOTAL_FLOWS_ID_MASK)
}

func (f *FlowGenerator) initFlow(meta *MetaPacket, key *FlowKey, now time.Duration) *FlowExtra {
	taggedFlow := &TaggedFlow{
		Flow: Flow{
			FlowKey:      *key,
			FlowID:       f.genFlowId(uint64(now), uint64(key.InPort)),
			TimeBitmap:   1,
			StartTime:    now,
			EndTime:      now,
			CurStartTime: now,
			VLAN:         meta.Vlan,
			EthType:      meta.EthType,
			CloseType:    CLOSE_TYPE_UNKNOWN,
		},
		Tag: Tag{PolicyData: meta.PolicyData},
	}
	flowExtra := f.FlowExtraPool.Get().(*FlowExtra)
	flowExtra.taggedFlow = taggedFlow
	flowExtra.flowState = FLOW_STATE_RAW
	flowExtra.recentTimesSec = now / time.Second
	flowExtra.reversed = false
	return flowExtra
}

func (f *FlowGenerator) updateFlowStateMachine(flowExtra *FlowExtra, flags uint8, reply, invalid bool) bool {
	var timeoutSec time.Duration
	var flowState FlowState
	closed := false
	taggedFlow := flowExtra.taggedFlow
	if reply {
		taggedFlow.FlowMetricsPeerDst.TCPFlags |= flags
	} else {
		taggedFlow.FlowMetricsPeerSrc.TCPFlags |= flags
	}
	if isExceptionFlags(flags, reply) || invalid {
		flowExtra.timeoutSec = f.Exception
		flowExtra.flowState = FLOW_STATE_EXCEPTION
		return false
	}
	if stateValue, ok := f.stateMachineMaster[flowExtra.flowState][flags&TCP_FLAG_MASK]; ok {
		timeoutSec = stateValue.timeoutSec
		flowState = stateValue.flowState
		closed = stateValue.closed
	} else {
		timeoutSec = f.Exception
		flowState = FLOW_STATE_EXCEPTION
		closed = false
	}
	if reply {
		if stateValue, ok := f.stateMachineSlave[flowExtra.flowState][flags&TCP_FLAG_MASK]; ok {
			timeoutSec = stateValue.timeoutSec
			flowState = stateValue.flowState
			closed = stateValue.closed
		}
	}
	flowExtra.timeoutSec = timeoutSec
	flowExtra.flowState = flowState
	if taggedFlow.FlowMetricsPeerSrc.TotalPacketCount == 0 || taggedFlow.FlowMetricsPeerDst.TotalPacketCount == 0 {
		flowExtra.timeoutSec = f.SingleDirection
	}
	return closed
}

func (f *FlowExtra) updatePlatformData(meta *MetaPacket, reply bool) {
	endpointData := meta.EndpointData
	var srcInfo, dstInfo *EndpointInfo
	if endpointData == nil {
		return
	}
	taggedFlow := f.taggedFlow
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

func (f *FlowExtra) reverseFlow() {
	taggedFlow := f.taggedFlow
	taggedFlow.TunnelInfo.Src, taggedFlow.TunnelInfo.Dst = taggedFlow.TunnelInfo.Dst, taggedFlow.TunnelInfo.Src
	taggedFlow.MACSrc, taggedFlow.MACDst = taggedFlow.MACDst, taggedFlow.MACSrc
	taggedFlow.IPSrc, taggedFlow.IPDst = taggedFlow.IPDst, taggedFlow.IPSrc
	taggedFlow.PortSrc, taggedFlow.PortDst = taggedFlow.PortDst, taggedFlow.PortSrc
	taggedFlow.GroupIDs0, taggedFlow.GroupIDs1 = taggedFlow.GroupIDs1, taggedFlow.GroupIDs0
	taggedFlow.FlowMetricsPeerSrc, taggedFlow.FlowMetricsPeerDst = FlowMetricsPeerSrc(taggedFlow.FlowMetricsPeerDst), FlowMetricsPeerDst(taggedFlow.FlowMetricsPeerSrc)
}

func (f *FlowGenerator) tryReverseFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) bool {
	taggedFlow := flowExtra.taggedFlow
	if flagContain(taggedFlow.FlowMetricsPeerSrc.TCPFlags|taggedFlow.FlowMetricsPeerDst.TCPFlags, TCP_SYN) || meta.TcpData == nil {
		return false
	}
	// if meta.Invalid is false, TcpData will not be nil
	if flagEqual(meta.TcpData.Flags&TCP_FLAG_MASK, TCP_SYN) && reply {
		flowExtra.reverseFlow()
		flowExtra.reversed = !flowExtra.reversed
		return true
	} else if flagEqual(meta.TcpData.Flags&TCP_FLAG_MASK, TCP_SYN|TCP_ACK) && !reply {
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
	maxArrTime := timeMax(taggedFlow.FlowMetricsPeerSrc.ArrTimeLast, taggedFlow.FlowMetricsPeerDst.ArrTimeLast)
	if taggedFlow.FlowMetricsPeerSrc.PacketCount == 0 && taggedFlow.FlowMetricsPeerDst.PacketCount == 0 {
		taggedFlow.CurStartTime = packetTimestamp
		taggedFlow.PolicyData = meta.PolicyData
		flowExtra.updatePlatformData(meta, reply)
	}
	if reply {
		if taggedFlow.FlowMetricsPeerDst.TotalPacketCount == 0 {
			taggedFlow.FlowMetricsPeerDst.ArrTime0 = packetTimestamp
		}
		if maxArrTime < packetTimestamp {
			taggedFlow.FlowMetricsPeerDst.ArrTimeLast = packetTimestamp
		} else {
			packetTimestamp = maxArrTime
			meta.Timestamp = maxArrTime
		}
		taggedFlow.FlowMetricsPeerDst.PacketCount++
		taggedFlow.FlowMetricsPeerDst.TotalPacketCount++
		taggedFlow.FlowMetricsPeerDst.ByteCount += bytes
		taggedFlow.FlowMetricsPeerDst.TotalByteCount += bytes
	} else {
		if taggedFlow.FlowMetricsPeerSrc.TotalPacketCount == 0 {
			taggedFlow.FlowMetricsPeerSrc.ArrTime0 = packetTimestamp
		}
		if maxArrTime < packetTimestamp {
			taggedFlow.FlowMetricsPeerSrc.ArrTimeLast = packetTimestamp
		} else {
			packetTimestamp = maxArrTime
			meta.Timestamp = maxArrTime
		}
		taggedFlow.FlowMetricsPeerSrc.PacketCount++
		taggedFlow.FlowMetricsPeerSrc.TotalPacketCount++
		taggedFlow.FlowMetricsPeerSrc.ByteCount += bytes
		taggedFlow.FlowMetricsPeerSrc.TotalByteCount += bytes
	}
	flowExtra.recentTimesSec = packetTimestamp / time.Second
	// a flow will report every minute and StartTime will be reset, so the value could not be overflow
	taggedFlow.TimeBitmap |= 1 << uint64(flowExtra.recentTimesSec-taggedFlow.StartTime/time.Second)
}

func (f *FlowExtra) setCurFlowInfo(now time.Duration, desireIntervalSec time.Duration) {
	taggedFlow := f.taggedFlow
	// desireIntervalSec should not be too small
	if (now-taggedFlow.StartTime)/time.Second > desireIntervalSec+REPORT_TOLERANCE {
		taggedFlow.EndTime = now - REPORT_TOLERANCE*time.Second
	} else {
		taggedFlow.EndTime = now
	}
	minArrTime := timeMin(taggedFlow.FlowMetricsPeerSrc.ArrTime0, taggedFlow.FlowMetricsPeerDst.ArrTime0)
	if minArrTime == 0 {
		minArrTime = timeMax(taggedFlow.FlowMetricsPeerSrc.ArrTime0, taggedFlow.FlowMetricsPeerDst.ArrTime0)
	}
	taggedFlow.Duration = timeMax(taggedFlow.FlowMetricsPeerSrc.ArrTimeLast, taggedFlow.FlowMetricsPeerDst.ArrTimeLast) - minArrTime
}

func (f *FlowExtra) resetCurFlowInfo(now time.Duration) {
	taggedFlow := f.taggedFlow
	taggedFlow.TimeBitmap = 0
	taggedFlow.StartTime = now
	taggedFlow.EndTime = now
	taggedFlow.CurStartTime = now
	taggedFlow.FlowMetricsPeerSrc.PacketCount = 0
	taggedFlow.FlowMetricsPeerDst.PacketCount = 0
	taggedFlow.FlowMetricsPeerSrc.ByteCount = 0
	taggedFlow.FlowMetricsPeerDst.ByteCount = 0
	taggedFlow.TcpPerfStats = nil
}

func (f *FlowExtra) calcCloseType(force bool) {
	if force {
		f.taggedFlow.CloseType = CLOSE_TYPE_FORCE_REPORT
		return
	}
	switch f.flowState {
	case FLOW_STATE_EXCEPTION:
		f.taggedFlow.CloseType = CLOSE_TYPE_UNKNOWN
	case FLOW_STATE_OPENING_1:
		fallthrough
	case FLOW_STATE_OPENING_2:
		f.taggedFlow.CloseType = CLOSE_TYPE_HALF_OPEN
	case FLOW_STATE_ESTABLISHED:
		f.taggedFlow.CloseType = CLOSE_TYPE_TIMEOUT
	case FLOW_STATE_CLOSING_TX1:
		fallthrough
	case FLOW_STATE_CLOSING_RX1:
		f.taggedFlow.CloseType = CLOSE_TYPE_HALF_CLOSE
	case FLOW_STATE_CLOSING_TX2:
		fallthrough
	case FLOW_STATE_CLOSING_RX2:
		fallthrough
	case FLOW_STATE_CLOSED:
		f.taggedFlow.CloseType = CLOSE_TYPE_FIN
	case FLOW_STATE_RESET:
		f.taggedFlow.CloseType = CLOSE_TYPE_RST
	default:
		log.Warningf("unexcepted 'unknown' close type, flow id is %d", f.taggedFlow.FlowID)
		f.taggedFlow.CloseType = CLOSE_TYPE_UNKNOWN
	}
}

func (f *FlowGenerator) processPackets(processBuffer []interface{}, gotSize int) {
	i := 0
loop:
	if i >= gotSize {
		f.packetHandler.Done()
		return
	}
	meta := processBuffer[i].(*MetaPacket)
	i++
	if meta.Protocol == layers.IPProtocolTCP {
		f.processTcpPacket(meta)
	} else if meta.Protocol == layers.IPProtocolUDP {
		f.processUdpPacket(meta)
	} else {
		f.processOtherIpPacket(meta)
	}
	goto loop
}

func (f *FlowGenerator) handlePackets() {
	metaPacketInQueue := f.metaPacketHeaderInQueue
	packetHandler := f.packetHandler
	recvBuffer := packetHandler.recvBuffer
	processBuffer := packetHandler.processBuffer
	gotSize := 0
loop:
	if !f.handleRunning {
		log.Info("flow fenerator packet handler exit")
		return
	}
	packetHandler.Add(1)
	go f.processPackets(processBuffer, gotSize)
	gotSize = metaPacketInQueue.Gets(recvBuffer)
	packetHandler.Wait()
	processBuffer, recvBuffer = recvBuffer, processBuffer
	goto loop
}

func (f *FlowGenerator) cleanHashMapByForce(hashMap []*FlowCache, start, end uint64, now time.Duration) {
	flowOutQueue := f.flowOutQueue
	forceReportIntervalSec := f.forceReportIntervalSec
	for _, flowCache := range hashMap[start:end] {
		if flowCache == nil {
			continue
		}
		flowCache.Lock()
		for e := flowCache.flowList.Front(); e != nil; {
			flowExtra := e.Value
			f.stats.CurrNumFlows--
			flowExtra.taggedFlow.TcpPerfStats = Report(flowExtra.metaFlowPerf, false, &f.perfCounter)
			flowExtra.setCurFlowInfo(now, forceReportIntervalSec)
			flowExtra.calcCloseType(false)
			flowOutQueue.Put(flowExtra.taggedFlow)
			e = e.Next()
		}
		flowCache.flowList.Init()
		flowCache.Unlock()
	}
}

func (f *FlowGenerator) cleanTimeoutHashMap(hashMap []*FlowCache, start, end, index uint64) {
	flowOutQueue := f.flowOutQueue
	forceReportIntervalSec := f.forceReportIntervalSec
	sleepDuration := f.minLoopIntervalSec * time.Second
	var flowOutBuffer [FLOW_OUT_BUFFER_CAP]interface{}
	flowOutNum := 0
	f.cleanWaitGroup.Add(1)

loop:
	time.Sleep(sleepDuration)
	now := time.Duration(time.Now().UnixNano())
	nowSec := now / time.Second
	cleanRangeSec := nowSec - f.minLoopIntervalSec
	maxFlowCacheLen := 0
	nonEmptyFlowCacheNum := 0
	for _, flowCache := range hashMap[start:end] {
		len := flowCache.flowList.Len()
		if len > 0 {
			nonEmptyFlowCacheNum++
		} else {
			continue
		}
		if maxFlowCacheLen <= len {
			maxFlowCacheLen = len
		}
		flowCache.Lock()
		for e := flowCache.flowList.Back(); e != nil; e = e.Prev() {
			flowExtra := e.Value
			// remaining flows are too new to output
			if flowExtra.recentTimesSec >= cleanRangeSec {
				break
			}
			if flowExtra.recentTimesSec+flowExtra.timeoutSec <= nowSec {
				flowExtra := e.Value
				taggedFlow := flowExtra.taggedFlow
				f.stats.CurrNumFlows--
				flowExtra.setCurFlowInfo(now, forceReportIntervalSec)
				flowExtra.calcCloseType(false)
				if f.servicePortDescriptor.judgeServiceDirection(taggedFlow.PortSrc, taggedFlow.PortDst) {
					flowExtra.reverseFlow()
					flowExtra.reversed = !flowExtra.reversed
				}
				taggedFlow.TcpPerfStats = Report(flowExtra.metaFlowPerf, flowExtra.reversed, &f.perfCounter)
				flowOutBuffer[flowOutNum] = taggedFlow
				flowOutNum++
				if flowOutNum >= FLOW_OUT_BUFFER_CAP {
					flowOutQueue.Put(flowOutBuffer[:flowOutNum]...)
					flowOutNum = 0
				}
				flowExtra.reset()
				f.FlowExtraPool.Put(flowExtra)
				flowCache.flowList.Remove(e)
			} else if flowExtra.taggedFlow.StartTime/time.Second+forceReportIntervalSec < nowSec {
				flowExtra := e.Value
				taggedFlow := flowExtra.taggedFlow
				flowExtra.setCurFlowInfo(now, forceReportIntervalSec)
				flowExtra.calcCloseType(true)
				if f.servicePortDescriptor.judgeServiceDirection(taggedFlow.PortSrc, taggedFlow.PortDst) {
					flowExtra.reverseFlow()
					flowExtra.reversed = !flowExtra.reversed
				}
				taggedFlow.TcpPerfStats = Report(flowExtra.metaFlowPerf, flowExtra.reversed, &f.perfCounter)
				if taggedFlow.FlowMetricsPeerSrc.PacketCount != 0 || taggedFlow.FlowMetricsPeerDst.PacketCount != 0 {
					putFlow := *taggedFlow
					flowOutBuffer[flowOutNum] = &putFlow
					flowOutNum++
				}
				if flowOutNum >= FLOW_OUT_BUFFER_CAP {
					flowOutQueue.Put(flowOutBuffer[:flowOutNum]...)
					flowOutNum = 0
				}
				flowExtra.resetCurFlowInfo(now)
			}
		}
		flowCache.Unlock()
	}
	if flowOutNum > 0 {
		flowOutQueue.Put(flowOutBuffer[:flowOutNum]...)
		flowOutNum = 0
	}
	f.stats.cleanRoutineFlowCacheNums[index] = nonEmptyFlowCacheNum
	f.stats.cleanRoutineMaxFlowCacheLens[index] = maxFlowCacheLen
	nonEmptyFlowCacheNum = 0
	maxFlowCacheLen = 0
	for i := 0; i < int(TIMOUT_PARALLEL_NUM); i++ {
		nonEmptyFlowCacheNum += f.stats.cleanRoutineFlowCacheNums[i]
		if maxFlowCacheLen < f.stats.cleanRoutineMaxFlowCacheLens[i] {
			maxFlowCacheLen = f.stats.cleanRoutineMaxFlowCacheLens[i]
		}
	}
	f.stats.NonEmptyFlowCacheNum = nonEmptyFlowCacheNum
	f.stats.MaxFlowCacheLen = maxFlowCacheLen
	if f.cleanRunning {
		goto loop
	}
	f.cleanHashMapByForce(hashMap, start, end, now)
	f.cleanWaitGroup.Done()
}

func (f *FlowGenerator) timeoutReport() {
	var flowCacheNum uint64
	f.cleanRunning = true
	if f.mapSize%f.timeoutParallelNum != 0 {
		flowCacheNum = f.mapSize/f.timeoutParallelNum + 1
	} else {
		flowCacheNum = f.mapSize / f.timeoutParallelNum
	}
	for i := uint64(0); i < f.timeoutParallelNum; i++ {
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
	log.Info("flow generator Started")
}

func (f *FlowGenerator) Stop() {
	if f.handleRunning {
		f.handleRunning = false
	}
	if f.cleanRunning {
		f.cleanRunning = false
		f.cleanWaitGroup.Wait()
	}
	log.Info("flow generator Stopped")
}

// create a new flow generator
func New(metaPacketHeaderInQueue QueueReader, flowOutQueue QueueWriter, forceReportIntervalSec time.Duration) *FlowGenerator {
	flowGenerator := &FlowGenerator{
		TimeoutConfig:           defaultTimeoutConfig,
		FastPath:                FastPath{FlowCacheHashMap: FlowCacheHashMap{make([]*FlowCache, HASH_MAP_SIZE), rand.Uint32(), HASH_MAP_SIZE, TIMOUT_PARALLEL_NUM}},
		metaPacketHeaderInQueue: metaPacketHeaderInQueue,
		flowOutQueue:            flowOutQueue,
		stats:                   FlowGeneratorStats{cleanRoutineFlowCacheNums: make([]int, TIMOUT_PARALLEL_NUM), cleanRoutineMaxFlowCacheLens: make([]int, TIMOUT_PARALLEL_NUM)},
		stateMachineMaster:      make([]map[uint8]*StateValue, FLOW_STATE_EXCEPTION+1),
		stateMachineSlave:       make([]map[uint8]*StateValue, FLOW_STATE_EXCEPTION+1),
		innerFlowKey:            &FlowKey{},
		packetHandler:           &PacketHandler{recvBuffer: make([]interface{}, 1024*64), processBuffer: make([]interface{}, 1024*64)},
		servicePortDescriptor:   getServiceDescriptorWithIANA(),
		forceReportIntervalSec:  forceReportIntervalSec,
		minLoopIntervalSec:      defaultTimeoutConfig.minTimeout(),
		flowLimitNum:            FLOW_LIMIT_NUM,
		handleRunning:           false,
		cleanRunning:            false,
		perfCounter:             NewFlowPerfCounter(),
	}
	if !flowGenerator.initFlowCache() {
		return nil
	}
	flowGenerator.initFastPathPool()
	flowGenerator.initStateMachineMaster()
	flowGenerator.initStateMachineSlave()
	flowGenerator.initMetaFlowPerfPool()
	RegisterCountable("flow_generator", EMPTY_TAG, flowGenerator)
	RegisterCountable(FP_NAME, EMPTY_TAG, &flowGenerator.perfCounter)
	log.Info("flow generator created")
	return flowGenerator
}

func (f *FlowGenerator) initMetaFlowPerfPool() {
	gc := func(b *MetaFlowPerfBlock) {
		f.metaFlowPerfPool.Put(b)
	}

	newBlock := func() interface{} {
		block := new(MetaFlowPerfBlock)
		runtime.SetFinalizer(block, gc)
		return block
	}

	f.metaFlowPerfPool = sync.Pool{New: newBlock}
	f.metaFlowPerfBlock = f.metaFlowPerfPool.Get().(*MetaFlowPerfBlock)
}

func (f *FlowGenerator) getMetaFlowPerfFromPool() *MetaFlowPerf {
	perf := &f.metaFlowPerfBlock[f.flowPerfBlockCursor]
	perf.resetMetaFlowPerf()

	f.flowPerfBlockCursor++
	if f.flowPerfBlockCursor >= len(*f.metaFlowPerfBlock) {
		f.metaFlowPerfBlock = f.metaFlowPerfPool.Get().(*MetaFlowPerfBlock)
		f.flowPerfBlockCursor = 0
	}

	return perf
}

func (f *FlowGenerator) checkIfDoFlowPerf(flowExtra *FlowExtra) bool {
	if flowExtra.taggedFlow.PolicyData == nil {
		return false
	}
	if flowExtra.taggedFlow.PolicyData.ActionList&ACTION_PERFORMANCE > 0 {
		if flowExtra.metaFlowPerf == nil {
			flowExtra.metaFlowPerf = f.getMetaFlowPerfFromPool()
		}
		return true
	}

	return false
}
