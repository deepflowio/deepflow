package flowgenerator

import (
	"container/list"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	. "gitlab.x.lan/yunshan/droplet-libs/stats"
)

var log = logging.MustGetLogger("flowgenerator")

func getFlowKey(meta *MetaPacket) *FlowKey {
	flowKey := &FlowKey{
		Exporter: *NewIPFromInt(meta.Exporter),
		IPSrc:    *NewIPFromInt(meta.IpSrc),
		IPDst:    *NewIPFromInt(meta.IpDst),
		Proto:    meta.Protocol,
		PortSrc:  meta.PortSrc,
		PortDst:  meta.PortDst,
		InPort0:  meta.InPort,
	}

	if tunnel := meta.Tunnel; tunnel != nil {
		flowKey.TunnelType = uint8(tunnel.Type)
		flowKey.TunnelID = tunnel.Id
		flowKey.TunnelIPSrc = tunnel.Src
		flowKey.TunnelIPDst = tunnel.Dst
	}

	return flowKey
}

// hash of the key L3, symmetric
func getKeyL3Hash(flowKey *FlowKey) uint64 {
	ipSrc := uint64(flowKey.IPSrc.Int())
	ipDst := uint64(flowKey.IPDst.Int())
	if ipSrc >= ipDst {
		return (ipSrc << 32) | ipDst
	}
	return ipSrc | (ipDst << 32)
}

// hash of the key L4, symmetric
func getKeyL4Hash(flowKey *FlowKey) uint64 {
	portSrc := uint64(flowKey.PortSrc)
	portDst := uint64(flowKey.PortDst)
	if portSrc >= portDst {
		return (portSrc << 16) | portDst
	}
	return (portDst << 16) | portSrc
}

func getQuinTupleHash(flowKey *FlowKey) uint64 {
	return getKeyL3Hash(flowKey) ^ ((uint64(flowKey.InPort0) << 32) | getKeyL4Hash(flowKey))
}

func isFromTrident(inPort0 uint32) bool {
	return inPort0&DEEPFLOW_POSITION_EXPORTER == DEEPFLOW_POSITION_EXPORTER
}

func (f *FlowExtra) MacEquals(meta *MetaPacket) bool {
	taggedFlow := f.taggedFlow
	flowMacSrc, flowMacDst := taggedFlow.MACSrc.Int(), taggedFlow.MACDst.Int()
	if flowMacSrc == meta.MacSrc && flowMacDst == meta.MacDst {
		return true
	}
	if flowMacSrc == meta.MacDst && flowMacDst == meta.MacSrc {
		return true
	}
	return false
}

func (f *FlowCache) keyMatch(meta *MetaPacket, key *FlowKey) (*FlowExtra, bool) {
	for e := f.flowList.Front(); e != nil; e = e.Next() {
		flowExtra := e.Value.(*FlowExtra)
		taggedFlow := flowExtra.taggedFlow
		if !taggedFlow.Exporter.Equals(&key.Exporter) || (isFromTrident(key.InPort0) && !flowExtra.MacEquals(meta)) {
			continue
		}
		if taggedFlow.TunnelType != key.TunnelType || taggedFlow.TunnelID != key.TunnelID {
			continue
		}
		if !(taggedFlow.TunnelIPSrc == key.TunnelIPSrc && taggedFlow.TunnelIPDst == key.TunnelIPDst) {
			continue
		} else if !(taggedFlow.TunnelIPSrc == key.TunnelIPDst && taggedFlow.TunnelIPDst == key.TunnelIPSrc) {
			continue
		}
		if taggedFlow.IPSrc.Equals(&key.IPSrc) && taggedFlow.IPDst.Equals(&key.IPDst) && taggedFlow.PortSrc == key.PortSrc && taggedFlow.PortDst == key.PortDst {
			f.flowList.MoveToFront(e)
			return flowExtra, false
		} else if taggedFlow.IPSrc.Equals(&key.IPDst) && taggedFlow.IPDst.Equals(&key.IPSrc) && taggedFlow.PortSrc == key.PortDst && taggedFlow.PortDst == key.PortSrc {
			f.flowList.MoveToFront(e)
			return flowExtra, true
		}
	}
	return nil, false
}

func (f *FlowGenerator) createFlowCache(cacheCap int, hash uint64) *FlowCache {
	newFlowCache := &FlowCache{
		capacity: cacheCap,
		flowList: list.New(),
	}
	f.hashMap[hash] = newFlowCache
	return newFlowCache
}

func (f *FlowGenerator) addFlow(flowCache *FlowCache, flowExtra *FlowExtra) *FlowExtra {
	if f.stats.CurrNumFlows >= f.flowLimitNum {
		return flowExtra
	}
	flowCache.flowList.PushFront(flowExtra)
	return nil
}

func (f *FlowGenerator) genFlowId(timestamp uint64, inPort uint64) uint64 {
	return ((inPort & IN_PORT_FLOW_ID_MASK) << 32) | ((timestamp & TIMER_FLOW_ID_MASK) << 32) | (f.stats.TotalNumFlows & TOTAL_FLOWS_ID_MASK)
}

func (f *FlowGenerator) initFlow(meta *MetaPacket, key *FlowKey) (*FlowExtra, bool, bool) {
	now := time.Duration(meta.Timestamp)
	taggedFlow := &TaggedFlow{
		Flow: Flow{
			FlowKey:      *key,
			FlowID:       f.genFlowId(uint64(now), uint64(key.InPort0)),
			StartTime:    now,
			EndTime:      now,
			CurStartTime: now,
			MACSrc:       *NewMACAddrFromInt(meta.MacSrc),
			MACDst:       *NewMACAddrFromInt(meta.MacDst),
			VLAN:         meta.Vlan,
			EthType:      meta.EthType,
			CloseType:    CLOSE_TYPE_UNKNOWN,
			TCPFlags0:    0,
			TCPFlags1:    0,
		},
		Tag: Tag{
			GroupIDs0: make([]uint32, 10),
			GroupIDs1: make([]uint32, 10),
		},
	}
	flowExtra := &FlowExtra{
		taggedFlow:     taggedFlow,
		metaFlowPerf:   NewMetaFlowPerf(),
		flowState:      FLOW_STATE_RAW,
		recentTimesSec: now / time.Second,
		reversed:       false,
	}
	if flagEqual(meta.TcpData.Flags&TCP_FLAG_MASK, TCP_SYN|TCP_ACK) {
		taggedFlow.IPSrc, taggedFlow.IPDst = taggedFlow.IPDst, taggedFlow.IPSrc
		taggedFlow.PortSrc, taggedFlow.PortDst = taggedFlow.PortDst, taggedFlow.PortSrc
		taggedFlow.TunnelIPSrc, taggedFlow.TunnelIPDst = taggedFlow.TunnelIPDst, taggedFlow.TunnelIPSrc
		taggedFlow.MACSrc = *NewMACAddrFromInt(meta.MacDst)
		taggedFlow.MACDst = *NewMACAddrFromInt(meta.MacSrc)
		taggedFlow.ArrTime10 = now
		taggedFlow.ArrTime1Last = now
		taggedFlow.TotalPacketCount1 = 1
		taggedFlow.PacketCount1 = 1
		taggedFlow.TotalByteCount1 = uint64(meta.PacketLen)
		taggedFlow.ByteCount1 = uint64(meta.PacketLen)
		flowExtra.updatePlatformData(meta, true)
		return flowExtra, f.updateFlowStateMachine(flowExtra, meta.TcpData.Flags, true), true
	} else {
		taggedFlow.MACSrc = *NewMACAddrFromInt(meta.MacSrc)
		taggedFlow.MACDst = *NewMACAddrFromInt(meta.MacDst)
		taggedFlow.ArrTime00 = now
		taggedFlow.ArrTime0Last = now
		taggedFlow.TotalPacketCount0 = 1
		taggedFlow.PacketCount0 = 1
		taggedFlow.TotalByteCount0 = uint64(meta.PacketLen)
		taggedFlow.ByteCount0 = uint64(meta.PacketLen)
		flowExtra.updatePlatformData(meta, false)
		return flowExtra, f.updateFlowStateMachine(flowExtra, meta.TcpData.Flags, false), false
	}
}

func (f *FlowGenerator) updateFlowStateMachine(flowExtra *FlowExtra, flags uint8, reply bool) bool {
	var timeoutSec time.Duration
	var flowState FlowState
	closed := false
	taggedFlow := flowExtra.taggedFlow
	if reply {
		taggedFlow.TCPFlags1 |= uint16(flags)
	} else {
		taggedFlow.TCPFlags0 |= uint16(flags)
	}
	if isExceptionFlags(flags, reply) {
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
	if taggedFlow.TotalPacketCount0 == 0 || taggedFlow.TotalPacketCount1 == 0 {
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
		taggedFlow.EpcID0 = srcInfo.L2EpcId
		taggedFlow.DeviceType0 = DeviceType(srcInfo.L2DeviceType)
		taggedFlow.DeviceID0 = srcInfo.L2DeviceId
		taggedFlow.IsL2End0 = srcInfo.L2End
		taggedFlow.IsL3End0 = srcInfo.L3End
		taggedFlow.L3EpcID0 = srcInfo.L3EpcId
		taggedFlow.L3DeviceType0 = DeviceType(srcInfo.L3DeviceType)
		taggedFlow.L3DeviceID0 = srcInfo.L3DeviceId
		taggedFlow.Host0 = srcInfo.HostIp
		taggedFlow.SubnetID0 = srcInfo.SubnetId
		// not to grow the cap of GroupIDs
		copy(taggedFlow.GroupIDs0, srcInfo.GroupIds)
	}
	if dstInfo != nil {
		taggedFlow.EpcID1 = dstInfo.L2EpcId
		taggedFlow.DeviceType1 = DeviceType(dstInfo.L2DeviceType)
		taggedFlow.DeviceID1 = dstInfo.L2DeviceId
		taggedFlow.IsL2End1 = dstInfo.L2End
		taggedFlow.IsL3End1 = dstInfo.L3End
		taggedFlow.L3EpcID1 = dstInfo.L3EpcId
		taggedFlow.L3DeviceType1 = DeviceType(dstInfo.L3DeviceType)
		taggedFlow.L3DeviceID1 = dstInfo.L3DeviceId
		taggedFlow.Host1 = dstInfo.HostIp
		taggedFlow.SubnetID1 = dstInfo.SubnetId
		copy(taggedFlow.GroupIDs1, dstInfo.GroupIds)
	}
}

func (f *FlowExtra) reverseFlow() {
	taggedFlow := f.taggedFlow
	taggedFlow.IPSrc, taggedFlow.IPDst = taggedFlow.IPDst, taggedFlow.IPSrc
	taggedFlow.PortSrc, taggedFlow.PortDst = taggedFlow.PortDst, taggedFlow.PortSrc
	taggedFlow.TunnelIPSrc, taggedFlow.TunnelIPDst = taggedFlow.TunnelIPDst, taggedFlow.TunnelIPSrc
	taggedFlow.MACSrc, taggedFlow.MACDst = taggedFlow.MACDst, taggedFlow.MACSrc
	taggedFlow.TCPFlags0, taggedFlow.TCPFlags1 = taggedFlow.TCPFlags1, taggedFlow.TCPFlags0
	taggedFlow.ByteCount0, taggedFlow.ByteCount1 = taggedFlow.ByteCount1, taggedFlow.ByteCount0
	taggedFlow.PacketCount0, taggedFlow.PacketCount1 = taggedFlow.PacketCount1, taggedFlow.PacketCount0
	taggedFlow.TotalByteCount0, taggedFlow.TotalByteCount1 = taggedFlow.TotalByteCount1, taggedFlow.TotalByteCount0
	taggedFlow.TotalPacketCount0, taggedFlow.TotalPacketCount1 = taggedFlow.TotalPacketCount1, taggedFlow.TotalPacketCount0
	taggedFlow.ArrTime00, taggedFlow.ArrTime10 = taggedFlow.ArrTime10, taggedFlow.ArrTime00
	taggedFlow.ArrTime0Last, taggedFlow.ArrTime1Last = taggedFlow.ArrTime1Last, taggedFlow.ArrTime0Last
	taggedFlow.SubnetID0, taggedFlow.SubnetID1 = taggedFlow.SubnetID1, taggedFlow.SubnetID0
	taggedFlow.L3DeviceType0, taggedFlow.L3DeviceType1 = taggedFlow.L3DeviceType1, taggedFlow.L3DeviceType0
	taggedFlow.L3DeviceID0, taggedFlow.L3DeviceID1 = taggedFlow.L3DeviceID1, taggedFlow.L3DeviceID0
	taggedFlow.L3EpcID0, taggedFlow.L3EpcID1 = taggedFlow.L3EpcID1, taggedFlow.L3EpcID0
	taggedFlow.Host0, taggedFlow.Host1 = taggedFlow.Host1, taggedFlow.Host0
	taggedFlow.EpcID0, taggedFlow.EpcID1 = taggedFlow.EpcID1, taggedFlow.EpcID0
	taggedFlow.DeviceType0, taggedFlow.DeviceType1 = taggedFlow.DeviceType1, taggedFlow.DeviceType0
	taggedFlow.DeviceID0, taggedFlow.DeviceID1 = taggedFlow.DeviceID1, taggedFlow.DeviceID0
	taggedFlow.IfIndex0, taggedFlow.IfIndex1 = taggedFlow.IfIndex1, taggedFlow.IfIndex0
	taggedFlow.IfType0, taggedFlow.IfType1 = taggedFlow.IfType1, taggedFlow.IfType0
	taggedFlow.IsL2End0, taggedFlow.IsL2End1 = taggedFlow.IsL2End1, taggedFlow.IsL2End0
	taggedFlow.IsL3End0, taggedFlow.IsL3End1 = taggedFlow.IsL3End1, taggedFlow.IsL3End0
}

func (f *FlowGenerator) tryReverseFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) bool {
	taggedFlow := flowExtra.taggedFlow
	if flagContain(uint8(taggedFlow.TCPFlags0|taggedFlow.TCPFlags1), TCP_SYN) {
		return false
	}
	if flagEqual(meta.TcpData.Flags&TCP_FLAG_MASK, TCP_SYN) && reply {
		flowExtra.reverseFlow()
		flowExtra.reversed = true
		return true
	} else if flagEqual(meta.TcpData.Flags&TCP_FLAG_MASK, TCP_SYN|TCP_ACK) && !reply {
		flowExtra.reverseFlow()
		flowExtra.reversed = true
		return true
	}
	return false
}

func (f *FlowGenerator) updateFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) (bool, bool) {
	taggedFlow := flowExtra.taggedFlow
	bytes := uint64(meta.PacketLen)
	packetTimestamp := meta.Timestamp
	maxArrTime := timeMax(taggedFlow.ArrTime0Last, taggedFlow.ArrTime1Last)
	if f.tryReverseFlow(flowExtra, meta, reply) {
		reply = !reply
	}
	if taggedFlow.PacketCount0 == 0 && taggedFlow.PacketCount1 == 0 {
		taggedFlow.CurStartTime = packetTimestamp
		flowExtra.updatePlatformData(meta, reply)
	}
	if reply {
		if taggedFlow.TotalPacketCount1 == 0 {
			taggedFlow.ArrTime10 = packetTimestamp
		}
		if maxArrTime < packetTimestamp {
			taggedFlow.ArrTime1Last = packetTimestamp
		} else {
			packetTimestamp = maxArrTime
			meta.Timestamp = maxArrTime
		}
		taggedFlow.PacketCount1++
		taggedFlow.TotalPacketCount1++
		taggedFlow.ByteCount1 += bytes
		taggedFlow.TotalByteCount1 += bytes
	} else {
		if taggedFlow.TotalPacketCount0 == 0 {
			taggedFlow.ArrTime00 = packetTimestamp
		}
		if maxArrTime < packetTimestamp {
			taggedFlow.ArrTime0Last = packetTimestamp
		} else {
			packetTimestamp = maxArrTime
			meta.Timestamp = maxArrTime
		}
		taggedFlow.PacketCount0++
		taggedFlow.TotalPacketCount0++
		taggedFlow.ByteCount0 += bytes
		taggedFlow.TotalByteCount0 += bytes
	}
	flowExtra.recentTimesSec = packetTimestamp / time.Second

	return f.updateFlowStateMachine(flowExtra, meta.TcpData.Flags, reply), reply
}

func (f *FlowExtra) setCurFlowInfo(now time.Duration, desireIntervalSec time.Duration) {
	taggedFlow := f.taggedFlow
	// desireIntervalSec should not be too small
	if now/time.Second-taggedFlow.StartTime/time.Second > desireIntervalSec+REPORT_TOLERANCE {
		taggedFlow.EndTime = now - REPORT_TOLERANCE*time.Second
	} else {
		taggedFlow.EndTime = now
	}
	taggedFlow.Duration = timeMax(taggedFlow.ArrTime0Last, taggedFlow.ArrTime1Last) - timeMin(taggedFlow.ArrTime00, taggedFlow.ArrTime10)
}

func (f *FlowExtra) resetCurFlowInfo(now time.Duration) {
	taggedFlow := f.taggedFlow
	taggedFlow.StartTime = now
	taggedFlow.EndTime = now
	taggedFlow.CurStartTime = now
	taggedFlow.PacketCount0 = 0
	taggedFlow.PacketCount1 = 0
	taggedFlow.ByteCount0 = 0
	taggedFlow.ByteCount1 = 0
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

func (f *FlowExtra) tryForceReport(flowOutQueue QueueWriter) {
	if f.taggedFlow.PacketCount0 != 0 || f.taggedFlow.PacketCount1 != 0 {
		taggedFlow := *f.taggedFlow
		flowOutQueue.Put(&taggedFlow)
	}
}

func (f *FlowGenerator) processPacket(meta *MetaPacket) {
	reply := false
	ok := false
	var flowExtra *FlowExtra
	flowKey := getFlowKey(meta)
	hash := getQuinTupleHash(flowKey)
	flowCache := f.hashMap[hash%HASH_MAP_SIZE]
	if flowCache == nil {
		flowCache = f.createFlowCache(FLOW_CACHE_CAP, hash%HASH_MAP_SIZE)
	}
	flowCache.Lock()
	if flowExtra, reply = flowCache.keyMatch(meta, flowKey); flowExtra != nil {
		if ok, reply = f.updateFlow(flowExtra, meta, reply); ok {
			f.stats.CurrNumFlows--
			flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(flowExtra.reversed)
			flowExtra.setCurFlowInfo(meta.Timestamp, f.forceReportIntervalSec)
			flowExtra.calcCloseType(false)
			f.flowOutQueue.Put(flowExtra.taggedFlow)
			// delete front from this FlowCache because flowExtra is moved to front in keyMatch()
			flowCache.flowList.Remove(flowCache.flowList.Front())
		} else {
			// reply is a sign relative to the flow direction, so if the flow is reversed then the sign should be changed
			flowExtra.metaFlowPerf.Update(meta, flowExtra.reversed != reply, flowExtra)
		}
	} else {
		closed := false
		flowExtra, closed, reply = f.initFlow(meta, flowKey)
		f.stats.TotalNumFlows++
		if closed {
			flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(false)
			flowExtra.setCurFlowInfo(meta.Timestamp, f.forceReportIntervalSec)
			flowExtra.calcCloseType(false)
			f.flowOutQueue.Put(flowExtra.taggedFlow)
		} else {
			flowExtra.metaFlowPerf.Update(meta, reply, flowExtra)

			if flowExtra == f.addFlow(flowCache, flowExtra) {
				// reach limit and output directly
				flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(false)
				flowExtra.setCurFlowInfo(meta.Timestamp, f.forceReportIntervalSec)
				flowExtra.taggedFlow.CloseType = CLOSE_TYPE_FLOOD
				f.flowOutQueue.Put(flowExtra.taggedFlow)
			} else {
				f.stats.CurrNumFlows++
			}
		}
	}
	flowCache.Unlock()
}

func (f *FlowGenerator) handle() {
	metaPacketHeaderInQueue := f.metaPacketHeaderInQueue
	for {
		meta := metaPacketHeaderInQueue.Get().(*MetaPacket)
		if !f.handleRunning {
			break
		}
		if meta.Protocol != layers.IPProtocolTCP {
			continue
		}
		f.processPacket(meta)
	}
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
			flowExtra := e.Value.(*FlowExtra)
			f.stats.CurrNumFlows--
			flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(false)
			flowExtra.setCurFlowInfo(now, forceReportIntervalSec)
			flowExtra.calcCloseType(false)
			flowOutQueue.Put(flowExtra.taggedFlow)
			e = e.Next()
		}
		flowCache.flowList.Init()
		flowCache.Unlock()
	}
}

func (f *FlowGenerator) cleanTimeoutHashMap(hashMap []*FlowCache, start, end uint64) {
	flowOutQueue := f.flowOutQueue
	forceReportIntervalSec := f.forceReportIntervalSec
	sleepDuration := f.minLoopIntervalSec * time.Second
	f.cleanWaitGroup.Add(1)

loop:
	time.Sleep(sleepDuration)
	now := time.Duration(time.Now().UnixNano())
	nowSec := now / time.Second
	cleanRangeSec := nowSec - f.minLoopIntervalSec
	for _, flowCache := range hashMap[start:end] {
		if flowCache == nil {
			continue
		}
		flowCache.Lock()
		for e := flowCache.flowList.Back(); e != nil; {
			var del *list.Element = nil
			flowExtra := e.Value.(*FlowExtra)
			// remaining flows are too new to output
			if flowExtra.recentTimesSec >= cleanRangeSec {
				break
			}
			// FIXME: modify flow direction by port and service list
			if flowExtra.recentTimesSec+flowExtra.timeoutSec <= nowSec {
				del = e
				f.stats.CurrNumFlows--
				flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(flowExtra.reversed)
				flowExtra.setCurFlowInfo(now, forceReportIntervalSec)
				flowExtra.calcCloseType(false)
				flowOutQueue.Put(flowExtra.taggedFlow)
			} else if flowExtra.taggedFlow.StartTime/time.Second+forceReportIntervalSec < nowSec {
				flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(flowExtra.reversed)
				flowExtra.setCurFlowInfo(now, forceReportIntervalSec)
				flowExtra.calcCloseType(true)
				flowExtra.tryForceReport(flowOutQueue)
				flowExtra.resetCurFlowInfo(now)
			}
			e = e.Prev()
			if del != nil {
				flowCache.flowList.Remove(del)
			}
		}
		flowCache.Unlock()
	}
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
			go f.cleanTimeoutHashMap(f.hashMap, start, end)
			log.Infof("clean goroutine %d (hashmap range %d to %d) created", i, start, end)
		} else {
			go f.cleanTimeoutHashMap(f.hashMap, start, f.mapSize)
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
		go f.handle()
	}
}

// we need these goroutines are thread safe
func (f *FlowGenerator) Start() {
	f.run()
	log.Info("Flow Generator Started")
}

func (f *FlowGenerator) Stop() {
	if f.handleRunning {
		f.handleRunning = false
	}
	if f.cleanRunning {
		f.cleanRunning = false
		f.cleanWaitGroup.Wait()
	}
	log.Info("Flow Generator Stopped")
}

// create a new flow generator
func New(metaPacketHeaderInQueue QueueReader, flowOutQueue QueueWriter, forceReportIntervalSec time.Duration) *FlowGenerator {
	flowGenerator := &FlowGenerator{
		TimeoutConfig:           defaultTimeoutConfig,
		FastPath:                FastPath{FlowCacheHashMap: FlowCacheHashMap{make([]*FlowCache, HASH_MAP_SIZE), HASH_MAP_SIZE, 4}},
		metaPacketHeaderInQueue: metaPacketHeaderInQueue,
		flowOutQueue:            flowOutQueue,
		stateMachineMaster:      make([]map[uint8]*StateValue, FLOW_STATE_EXCEPTION+1),
		stateMachineSlave:       make([]map[uint8]*StateValue, FLOW_STATE_EXCEPTION+1),
		forceReportIntervalSec:  forceReportIntervalSec,
		minLoopIntervalSec:      defaultTimeoutConfig.minTimeout(),
		flowLimitNum:            FLOW_LIMIT_NUM,
		handleRunning:           false,
		cleanRunning:            false,
	}
	flowGenerator.initStateMachineMaster()
	flowGenerator.initStateMachineSlave()
	RegisterCountable("flow_gen", EMPTY_TAG, flowGenerator)
	log.Info("Flow Generator created")
	return flowGenerator
}
