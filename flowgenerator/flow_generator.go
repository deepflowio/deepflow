package flowgenerator

import (
	"math/rand"
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
		if !flowExtra.TunnelMatch(key) {
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

func (f *FlowGenerator) initFlow(meta *MetaPacket, key *FlowKey) (*FlowExtra, bool, bool) {
	now := time.Duration(meta.Timestamp)
	taggedFlow := &TaggedFlow{
		Flow: Flow{
			FlowKey:            *key,
			FlowID:             f.genFlowId(uint64(now), uint64(key.InPort)),
			TimeBitmap:         1,
			StartTime:          now,
			EndTime:            now,
			CurStartTime:       now,
			VLAN:               meta.Vlan,
			EthType:            meta.EthType,
			CloseType:          CLOSE_TYPE_UNKNOWN,
			FlowMetricsPeerSrc: FlowMetricsPeerSrc{TCPFlags: 0},
			FlowMetricsPeerDst: FlowMetricsPeerDst{TCPFlags: 0},
		},
		Tag: Tag{PolicyData: meta.PolicyData},
	}
	flowExtra := &FlowExtra{
		taggedFlow:     taggedFlow,
		metaFlowPerf:   NewMetaFlowPerf(&f.perfCounter),
		flowState:      FLOW_STATE_RAW,
		recentTimesSec: now / time.Second,
		reversed:       false,
	}
	var flags uint8 = 0
	if meta.TcpData != nil {
		flags = meta.TcpData.Flags
	}
	if flagEqual(flags&TCP_FLAG_MASK, TCP_SYN|TCP_ACK) {
		taggedFlow.IPSrc, taggedFlow.IPDst = taggedFlow.IPDst, taggedFlow.IPSrc
		taggedFlow.PortSrc, taggedFlow.PortDst = taggedFlow.PortDst, taggedFlow.PortSrc
		taggedFlow.TunnelInfo.Src, taggedFlow.TunnelInfo.Dst = taggedFlow.TunnelInfo.Dst, taggedFlow.TunnelInfo.Src
		taggedFlow.FlowMetricsPeerDst.ArrTime0 = now
		taggedFlow.FlowMetricsPeerDst.ArrTimeLast = now
		taggedFlow.FlowMetricsPeerDst.TotalPacketCount = 1
		taggedFlow.FlowMetricsPeerDst.PacketCount = 1
		taggedFlow.FlowMetricsPeerDst.TotalByteCount = uint64(meta.PacketLen)
		taggedFlow.FlowMetricsPeerDst.ByteCount = uint64(meta.PacketLen)
		flowExtra.updatePlatformData(meta, true)
		return flowExtra, f.updateFlowStateMachine(flowExtra, flags, true, meta.Invalid), true
	} else {
		taggedFlow.FlowMetricsPeerSrc.ArrTime0 = now
		taggedFlow.FlowMetricsPeerSrc.ArrTimeLast = now
		taggedFlow.FlowMetricsPeerSrc.TotalPacketCount = 1
		taggedFlow.FlowMetricsPeerSrc.PacketCount = 1
		taggedFlow.FlowMetricsPeerSrc.TotalByteCount = uint64(meta.PacketLen)
		taggedFlow.FlowMetricsPeerSrc.ByteCount = uint64(meta.PacketLen)
		flowExtra.updatePlatformData(meta, false)
		return flowExtra, f.updateFlowStateMachine(flowExtra, flags, false, meta.Invalid), false
	}
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

func (f *FlowGenerator) updateFlow(flowExtra *FlowExtra, meta *MetaPacket, reply bool) (bool, bool) {
	taggedFlow := flowExtra.taggedFlow
	bytes := uint64(meta.PacketLen)
	packetTimestamp := meta.Timestamp
	maxArrTime := timeMax(taggedFlow.FlowMetricsPeerSrc.ArrTimeLast, taggedFlow.FlowMetricsPeerDst.ArrTimeLast)
	var flags uint8 = 0
	if meta.TcpData != nil {
		flags = meta.TcpData.Flags
	}
	if f.tryReverseFlow(flowExtra, meta, reply) {
		reply = !reply
	}
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

	return f.updateFlowStateMachine(flowExtra, flags, reply, meta.Invalid), reply
}

func (f *FlowExtra) setCurFlowInfo(now time.Duration, desireIntervalSec time.Duration) {
	taggedFlow := f.taggedFlow
	// desireIntervalSec should not be too small
	if now/time.Second-taggedFlow.StartTime/time.Second > desireIntervalSec+REPORT_TOLERANCE {
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

func (f *FlowExtra) tryForceReport(flowOutQueue QueueWriter) {
	if f.taggedFlow.FlowMetricsPeerSrc.PacketCount != 0 || f.taggedFlow.FlowMetricsPeerDst.PacketCount != 0 {
		taggedFlow := *f.taggedFlow
		flowOutQueue.Put(&taggedFlow)
	}
}

func (f *FlowGenerator) processPacket(meta *MetaPacket) {
	reply := false
	ok := false
	var flowExtra *FlowExtra
	flowKey := f.genFlowKey(meta)
	hash := f.getQuinTupleHash(flowKey)
	flowCache := f.hashMap[hash%HASH_MAP_SIZE]
	// keyMatch is goroutine safety
	if flowExtra, reply = flowCache.keyMatch(meta, flowKey); flowExtra != nil {
		if ok, reply = f.updateFlow(flowExtra, meta, reply); ok {
			f.stats.CurrNumFlows--
			flowExtra.setCurFlowInfo(meta.Timestamp, f.forceReportIntervalSec)
			flowExtra.calcCloseType(false)
			if f.servicePortDescriptor.judgeServiceDirection(flowExtra.taggedFlow.PortSrc, flowExtra.taggedFlow.PortDst) {
				flowExtra.reverseFlow()
				flowExtra.reversed = !flowExtra.reversed
			}
			flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(flowExtra.reversed, &f.perfCounter)
			f.flowOutQueue.Put(flowExtra.taggedFlow)
			// delete front from this FlowCache because flowExtra is moved to front in keyMatch()
			flowCache.Lock()
			flowCache.flowList.RemoveFront()
			flowCache.Unlock()
		} else {
			// reply is a sign relative to the flow direction, so if the flow is reversed then the sign should be changed
			flowExtra.metaFlowPerf.Update(meta, flowExtra.reversed != reply, flowExtra, &f.perfCounter)
		}
	} else {
		closed := false
		flowExtra, closed, reply = f.initFlow(meta, flowKey)
		f.stats.TotalNumFlows++
		if closed {
			flowExtra.setCurFlowInfo(meta.Timestamp, f.forceReportIntervalSec)
			flowExtra.calcCloseType(false)
			if f.servicePortDescriptor.judgeServiceDirection(flowExtra.taggedFlow.PortSrc, flowExtra.taggedFlow.PortDst) {
				flowExtra.reverseFlow()
				flowExtra.reversed = !flowExtra.reversed
			}
			flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(flowExtra.reversed, &f.perfCounter)
			f.flowOutQueue.Put(flowExtra.taggedFlow)
		} else {
			flowExtra.metaFlowPerf.Update(meta, reply, flowExtra, &f.perfCounter)
			if flowExtra == f.addFlow(flowCache, flowExtra) {
				// reach limit and output directly
				flowExtra.setCurFlowInfo(meta.Timestamp, f.forceReportIntervalSec)
				flowExtra.taggedFlow.CloseType = CLOSE_TYPE_FLOOD
				if f.servicePortDescriptor.judgeServiceDirection(flowExtra.taggedFlow.PortSrc, flowExtra.taggedFlow.PortDst) {
					flowExtra.reverseFlow()
					flowExtra.reversed = !flowExtra.reversed
				}
				flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(flowExtra.reversed, &f.perfCounter)
				f.flowOutQueue.Put(flowExtra.taggedFlow)
			} else {
				f.stats.CurrNumFlows++
			}
		}
	}
}

func (f *FlowGenerator) handle() {
	metaPacketInQueue := f.metaPacketHeaderInQueue
	metaPacketBuffer := make([]interface{}, 1024*16)
loop:
	if !f.handleRunning {
		log.Info("flow fenerator packet handler exit")
		return
	}
	gotSize := metaPacketInQueue.Gets(metaPacketBuffer)
	for _, e := range metaPacketBuffer[:gotSize] {
		meta := e.(*MetaPacket)
		if meta.Protocol != layers.IPProtocolTCP {
			continue
		}
		f.processPacket(meta)
	}
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
			flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(false, &f.perfCounter)
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
	forceReportBuffer := NewListFlowExtra()
	otherReportBuffer := NewListFlowExtra()
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
				otherReportBuffer.PushFront(flowExtra)
				flowCache.flowList.Remove(e)
			} else if flowExtra.taggedFlow.StartTime/time.Second+forceReportIntervalSec < nowSec {
				forceReportBuffer.PushFront(flowExtra)
			}
		}
		flowCache.Unlock()
	}
	// real output
	for e := otherReportBuffer.Front(); e != nil; e = e.Next() {
		flowExtra := e.Value
		taggedFlow := flowExtra.taggedFlow
		f.stats.CurrNumFlows--
		flowExtra.setCurFlowInfo(now, forceReportIntervalSec)
		flowExtra.calcCloseType(false)
		if f.servicePortDescriptor.judgeServiceDirection(taggedFlow.PortSrc, taggedFlow.PortDst) {
			flowExtra.reverseFlow()
			flowExtra.reversed = !flowExtra.reversed
		}
		taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(flowExtra.reversed, &f.perfCounter)
		if taggedFlow.FlowMetricsPeerSrc.PacketCount != 0 || taggedFlow.FlowMetricsPeerDst.PacketCount != 0 {
			putFlow := *taggedFlow
			flowOutQueue.Put(&putFlow)
		}
		flowExtra.resetCurFlowInfo(now)
	}
	otherReportBuffer.Init()
	for e := forceReportBuffer.Front(); e != nil; e = e.Next() {
		flowExtra := e.Value
		flowExtra.setCurFlowInfo(now, forceReportIntervalSec)
		flowExtra.calcCloseType(true)
		if f.servicePortDescriptor.judgeServiceDirection(flowExtra.taggedFlow.PortSrc, flowExtra.taggedFlow.PortDst) {
			flowExtra.reverseFlow()
			flowExtra.reversed = !flowExtra.reversed
		}
		flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(flowExtra.reversed, &f.perfCounter)
		flowExtra.tryForceReport(flowOutQueue)
		flowExtra.resetCurFlowInfo(now)
	}
	forceReportBuffer.Init()
	if f.stats.MaxFlowCacheLen < maxFlowCacheLen {
		f.stats.MaxFlowCacheLen = maxFlowCacheLen
	}
	f.stats.cleanRoutineFlowCacheNums[index] = nonEmptyFlowCacheNum
	nonEmptyFlowCacheNum = 0
	for num := range f.stats.cleanRoutineFlowCacheNums {
		nonEmptyFlowCacheNum += num
	}
	f.stats.NonEmptyFlowCacheNum = nonEmptyFlowCacheNum
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
		go f.handle()
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
		stats:                   FlowGeneratorStats{cleanRoutineFlowCacheNums: make([]int, TIMOUT_PARALLEL_NUM)},
		stateMachineMaster:      make([]map[uint8]*StateValue, FLOW_STATE_EXCEPTION+1),
		stateMachineSlave:       make([]map[uint8]*StateValue, FLOW_STATE_EXCEPTION+1),
		innerFlowKey:            &FlowKey{},
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
	flowGenerator.initStateMachineMaster()
	flowGenerator.initStateMachineSlave()
	RegisterCountable("flow_generator", EMPTY_TAG, flowGenerator)
	RegisterCountable(FP_NAME, EMPTY_TAG, &flowGenerator.perfCounter)
	log.Info("flow generator created")
	return flowGenerator
}
