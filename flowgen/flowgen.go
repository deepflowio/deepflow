package flowgen

import (
	"container/list"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/policy"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	. "gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"

	"gitlab.x.lan/yunshan/droplet/handler"
	. "gitlab.x.lan/yunshan/droplet/utils"
)

var log = logging.MustGetLogger("flowgen")

func getFlowKey(meta *handler.MetaPacket) *FlowKey {
	flowKey := &FlowKey{
		Exporter: *NewIPFromInt(IpToUint32(meta.Exporter)),
		IPSrc:    *NewIPFromInt(meta.IpSrc),
		IPDst:    *NewIPFromInt(meta.IpDst),
		Proto:    meta.Proto,
		PortSrc:  meta.PortSrc,
		PortDst:  meta.PortDst,
		InPort0:  meta.InPort,
	}

	if meta.TunnelType != handler.TUNNEL_TYPE_NONE {
		flowKey.TunnelType = uint8(meta.TunnelType)
		flowKey.TunnelID = meta.TunnelId
		flowKey.TunnelIPSrc = IpToUint32(meta.TunnelSrc)
		flowKey.TunnelIPDst = IpToUint32(meta.TunnelDst)
	}

	return flowKey
}

// hash of the key L3, symmetric
// FIXME: consider Tnl
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
	inPort0 := uint64(flowKey.InPort0)
	return getKeyL3Hash(flowKey) ^ ((inPort0 << 32) | getKeyL4Hash(flowKey))
}

func isFromTrident(flowKey *FlowKey) bool {
	return flowKey.InPort0&0x30000000 > 0
}

func (f *FlowExtra) MacEquals(meta *handler.MetaPacket) bool {
	taggedFlow := f.taggedFlow
	flowMacSrc, flowMacDst := taggedFlow.MACSrc.Int(), taggedFlow.MACDst.Int()
	metaPktHdrMacSrc, metaPktHdrMacDst := Mac2Uint64(meta.MacSrc), Mac2Uint64(meta.MacDst)
	if flowMacSrc == metaPktHdrMacSrc && flowMacDst == metaPktHdrMacDst {
		return true
	}
	if flowMacSrc == metaPktHdrMacDst && flowMacDst == metaPktHdrMacSrc {
		return true
	}
	return false
}

// FIXME: need a fast way to compare like memcmp
func (f *FlowCache) keyMatch(meta *handler.MetaPacket, key *FlowKey) (*FlowExtra, bool) {
	for e := f.flowList.Front(); e != nil; e = e.Next() {
		flowExtra := e.Value.(*FlowExtra)
		flowKey := &flowExtra.taggedFlow.FlowKey
		if flowKey.InPort0 != key.InPort0 || !flowKey.Exporter.Equals(&key.Exporter) {
			continue
		}
		if flowKey.TunnelType != key.TunnelType || flowKey.TunnelID != key.TunnelID {
			continue
		}
		if !(flowKey.TunnelIPSrc == key.TunnelIPSrc && flowKey.TunnelIPDst == key.TunnelIPDst) {
			continue
		} else if !(flowKey.TunnelIPSrc == key.TunnelIPDst && flowKey.TunnelIPDst == key.TunnelIPSrc) {
			continue
		}
		if isFromTrident(key) && !flowExtra.MacEquals(meta) {
			continue
		}
		if flowKey.IPSrc.Equals(&key.IPSrc) && flowKey.IPDst.Equals(&key.IPDst) {
			if flowKey.PortSrc == key.PortSrc && flowKey.PortDst == key.PortDst {
				return flowExtra, false
			}
		} else if flowKey.IPSrc.Equals(&key.IPDst) && flowKey.IPDst.Equals(&key.IPSrc) {
			if flowKey.PortSrc == key.PortDst && flowKey.PortDst == key.PortSrc {
				return flowExtra, true
			}
		}
	}
	return nil, false
}

func (f *FastPath) createFlowCache(cacheCap int, hash uint64) *FlowCache {
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

func (f *FlowGenerator) initFlow(meta *handler.MetaPacket, key *FlowKey) (*FlowExtra, bool) {
	now := time.Duration(meta.Timestamp)
	taggedFlow := &TaggedFlow{
		Flow: Flow{
			FlowKey:      *key,
			FlowID:       f.genFlowId(uint64(now), uint64(key.InPort0)),
			StartTime:    now,
			EndTime:      now,
			CurStartTime: now,
			MACSrc:       *NewMACAddrFromString(meta.MacSrc.String()),
			MACDst:       *NewMACAddrFromString(meta.MacDst.String()),
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
		flowState:      FLOW_STATE_RAW,
		recentTimesSec: now / time.Second,
	}
	if flagEqual(meta.TcpData.Flags&TCP_FLAG_MASK, TCP_SYN|TCP_ACK) {
		taggedFlow.IPSrc, taggedFlow.IPDst = taggedFlow.IPDst, taggedFlow.IPSrc
		taggedFlow.PortSrc, taggedFlow.PortDst = taggedFlow.PortDst, taggedFlow.PortSrc
		taggedFlow.TunnelIPSrc, taggedFlow.TunnelIPDst = taggedFlow.TunnelIPDst, taggedFlow.TunnelIPSrc
		taggedFlow.MACSrc = *NewMACAddrFromString(meta.MacDst.String())
		taggedFlow.MACDst = *NewMACAddrFromString(meta.MacSrc.String())
		taggedFlow.ArrTime10 = now
		taggedFlow.ArrTime1Last = now
		taggedFlow.TotalPacketCount1 = 1
		taggedFlow.PacketCount1 = 1
		taggedFlow.TotalByteCount1 = uint64(meta.PacketLen)
		taggedFlow.ByteCount1 = uint64(meta.PacketLen)
		taggedFlow.IsL2End0 = meta.L2End1
		taggedFlow.IsL2End1 = meta.L2End0
		flowExtra.updatePlatformData(meta, true)
		return flowExtra, flowExtra.updateTCPStateMachine(meta.TcpData.Flags, true)
	} else {
		taggedFlow.MACSrc = *NewMACAddrFromString(meta.MacSrc.String())
		taggedFlow.MACDst = *NewMACAddrFromString(meta.MacDst.String())
		taggedFlow.ArrTime00 = now
		taggedFlow.ArrTime0Last = now
		taggedFlow.TotalPacketCount0 = 1
		taggedFlow.PacketCount0 = 1
		taggedFlow.TotalByteCount0 = uint64(meta.PacketLen)
		taggedFlow.ByteCount0 = uint64(meta.PacketLen)
		taggedFlow.IsL2End0 = meta.L2End0
		taggedFlow.IsL2End1 = meta.L2End1
		flowExtra.updatePlatformData(meta, false)
		return flowExtra, flowExtra.updateTCPStateMachine(meta.TcpData.Flags, false)
	}
}

func isExceptionState(flags uint8, reply bool) bool {
	switch flags & TCP_FLAG_MASK {
	case TCP_SYN:
		return false
	case TCP_SYN | TCP_ACK:
		return false
	case TCP_FIN:
		return false
	case TCP_FIN | TCP_ACK:
		return false
	case TCP_FIN | TCP_PSH | TCP_ACK:
		return false
	case TCP_RST:
		return false
	case TCP_RST | TCP_ACK:
		return false
	case TCP_RST | TCP_PSH | TCP_ACK:
		return false
	case TCP_ACK:
		return false
	case TCP_PSH:
		return false
	case TCP_PSH | TCP_ACK:
		return false
	case TCP_PSH | TCP_ACK | TCP_URG:
		return false
	default:
		return true
	}
}

func (f *FlowExtra) updateTCPStateMachine(flags uint8, reply bool) bool {
	taggedFlow := f.taggedFlow
	if reply {
		taggedFlow.TCPFlags1 |= uint16(flags)
	} else {
		taggedFlow.TCPFlags0 |= uint16(flags)
	}
	if isExceptionState(flags, reply) {
		f.timeoutSec = innerTimeoutConfig.Exception
		f.flowState = FLOW_STATE_EXCEPTION
		return false
	}
	switch f.flowState {
	case FLOW_STATE_RAW:
		if flagContain(flags, TCP_RST) {
			f.timeoutSec = innerTimeoutConfig.Opening
			f.flowState = FLOW_STATE_RESET
		} else if flagEqual(flags&TCP_FLAG_MASK, TCP_SYN) {
			f.timeoutSec = innerTimeoutConfig.Opening
			f.flowState = FLOW_STATE_OPENING_1
		} else if flagEqual(flags&TCP_FLAG_MASK, TCP_SYN|TCP_ACK) {
			f.timeoutSec = innerTimeoutConfig.Opening
			f.flowState = FLOW_STATE_OPENING_2
		} else if !reply && flagContain(flags, TCP_FIN) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_CLOSING_TX1
		} else if reply && flagContain(flags, TCP_FIN) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_CLOSING_RX1
		} else if flagContain(flags, TCP_PSH) || flagContain(flags, TCP_ACK) {
			f.timeoutSec = innerTimeoutConfig.Established
			f.flowState = FLOW_STATE_ESTABLISHED
		}
	case FLOW_STATE_OPENING_1:
		if flagContain(flags, TCP_RST) {
			f.timeoutSec = innerTimeoutConfig.Opening
			f.flowState = FLOW_STATE_RESET
		} else if reply && flagEqual(flags&TCP_FLAG_MASK, TCP_SYN|TCP_ACK) {
			f.timeoutSec = innerTimeoutConfig.Opening
			f.flowState = FLOW_STATE_OPENING_2
		} else if reply && flagEqual(flags&TCP_FLAG_MASK, TCP_SYN) {
			f.timeoutSec = innerTimeoutConfig.Exception
			f.flowState = FLOW_STATE_EXCEPTION
		} else if !reply && flagContain(flags, TCP_FIN) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_CLOSING_TX1
		} else if reply && flagContain(flags, TCP_FIN) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_CLOSING_RX1
		} else {
			f.timeoutSec = innerTimeoutConfig.Established
			f.flowState = FLOW_STATE_ESTABLISHED
		}
	case FLOW_STATE_OPENING_2:
		if flagContain(flags, TCP_RST) {
			f.timeoutSec = innerTimeoutConfig.Opening
			f.flowState = FLOW_STATE_RESET
		} else if flagContain(flags, TCP_ACK) {
			f.timeoutSec = innerTimeoutConfig.Established
			f.flowState = FLOW_STATE_ESTABLISHED
		} else if !reply && flagContain(flags, TCP_FIN) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_CLOSING_TX1
		} else if reply && flagContain(flags, TCP_FIN) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_CLOSING_RX1
		} else {
			f.timeoutSec = innerTimeoutConfig.Established
			f.flowState = FLOW_STATE_ESTABLISHED
		}
	case FLOW_STATE_ESTABLISHED:
		if flagContain(flags, TCP_RST) {
			f.timeoutSec = innerTimeoutConfig.EstablishedRst
			f.flowState = FLOW_STATE_RESET
		} else if !reply && flagContain(flags, TCP_FIN) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_CLOSING_TX1
		} else if reply && flagContain(flags, TCP_FIN) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_CLOSING_RX1
		}
	case FLOW_STATE_CLOSING_TX1:
		if flagContain(flags, TCP_RST) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_RESET
		} else if reply && flagContain(flags, TCP_FIN) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_CLOSING_TX2
		}
	case FLOW_STATE_CLOSING_RX1:
		if flagContain(flags, TCP_RST) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_RESET
		} else if flagContain(flags, TCP_FIN) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_CLOSING_RX2
		}
	case FLOW_STATE_CLOSING_TX2:
		if flagContain(flags, TCP_RST) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_RESET
		} else if flagEqual(flags&TCP_FLAG_MASK, TCP_ACK) {
			f.timeoutSec = innerTimeoutConfig.ClosedFin
			f.flowState = FLOW_STATE_CLOSED
			return true
		}
	case FLOW_STATE_CLOSING_RX2:
		if flagContain(flags, TCP_RST) {
			f.timeoutSec = innerTimeoutConfig.Closing
			f.flowState = FLOW_STATE_RESET
		} else if reply && flagEqual(flags&TCP_FLAG_MASK, TCP_ACK) {
			f.timeoutSec = innerTimeoutConfig.ClosedFin
			f.flowState = FLOW_STATE_CLOSED
			return true
		}
	case FLOW_STATE_RESET:
		return false
	case FLOW_STATE_EXCEPTION:
		return false
	default:
		log.Warningf("unexpected flow state: %d, set as exception state by force", f.flowState)
		f.timeoutSec = innerTimeoutConfig.Exception
		f.flowState = FLOW_STATE_EXCEPTION
	}
	if taggedFlow.TotalPacketCount0 == 0 || taggedFlow.TotalPacketCount1 == 0 {
		f.timeoutSec = innerTimeoutConfig.SingleDirection
	}
	return false
}

func (f *FlowExtra) updatePlatformData(meta *handler.MetaPacket, reply bool) {
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
		taggedFlow.IsL3End0 = srcInfo.L3End
		taggedFlow.L3EpcID0 = srcInfo.L3EpcId
		taggedFlow.L3DeviceType0 = DeviceType(srcInfo.L3DeviceType)
		taggedFlow.L3DeviceID0 = srcInfo.L3DeviceId
		taggedFlow.SubnetID0 = srcInfo.SubnetId
		// FIXME: not to grow the cap of GroupIDs
		copy(taggedFlow.GroupIDs0, srcInfo.GroupIds)
		// use src host ip as host of flow
		taggedFlow.Host = *NewIPFromInt(srcInfo.HostIp)
	}
	if dstInfo != nil {
		taggedFlow.EpcID1 = dstInfo.L2EpcId
		taggedFlow.DeviceType1 = DeviceType(dstInfo.L2DeviceType)
		taggedFlow.DeviceID1 = dstInfo.L2DeviceId
		taggedFlow.IsL3End1 = dstInfo.L3End
		taggedFlow.L3EpcID1 = dstInfo.L3EpcId
		taggedFlow.L3DeviceType1 = DeviceType(dstInfo.L3DeviceType)
		taggedFlow.L3DeviceID1 = dstInfo.L3DeviceId
		taggedFlow.SubnetID1 = dstInfo.SubnetId
		copy(taggedFlow.GroupIDs1, srcInfo.GroupIds)
	}
}

func (f *FlowExtra) updateFlow(meta *handler.MetaPacket, reply bool) bool {
	taggedFlow := f.taggedFlow
	bytes := uint64(meta.PacketLen)
	packetTimestamp := meta.Timestamp
	maxArrTime := timeMax(taggedFlow.ArrTime0Last, taggedFlow.ArrTime1Last)
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
	f.recentTimesSec = packetTimestamp / time.Second
	f.updatePlatformData(meta, reply)

	return f.updateTCPStateMachine(meta.TcpData.Flags, reply)
}

func (f *FlowExtra) setCurFlowInfo(now time.Duration, desireIntervalSec time.Duration) {
	taggedFlow := f.taggedFlow
	// desireIntervalSec should not be too small
	if now/time.Second-taggedFlow.StartTime/time.Second > desireIntervalSec+10 {
		taggedFlow.EndTime = now - 10*time.Second
	} else {
		taggedFlow.EndTime = now
	}
	taggedFlow.Duration = timeMax(taggedFlow.ArrTime0Last, taggedFlow.ArrTime1Last) - timeMin(taggedFlow.ArrTime00, taggedFlow.ArrTime10)
}

func (f *FlowExtra) resetCurFlowInfo(now time.Duration) {
	taggedFlow := f.taggedFlow
	taggedFlow.StartTime = now
	taggedFlow.EndTime = now
	taggedFlow.CurStartTime = 0
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

func (f *FlowExtra) initFlowInfo(flow *TaggedFlow, state FlowState, reply bool) *FlowInfo {
	return &FlowInfo{
		FlowState:         state,
		Direction:         reply,
		FlowID:            flow.FlowID,
		TotalPacketCount0: flow.TotalPacketCount0,
		TotalPacketCount1: flow.TotalPacketCount1,
		ArrTime0Last:      flow.ArrTime0Last,
		ArrTime1Last:      flow.ArrTime1Last,
		TcpFlags0:         flow.TCPFlags0,
		TcpFlags1:         flow.TCPFlags1,
	}
}

func (f *FlowGenerator) processPacket(meta *handler.MetaPacket) {
	reply := false
	var flowExtra *FlowExtra
	fastPath := &f.fastPath
	flowKey := getFlowKey(meta)
	hash := getQuinTupleHash(flowKey)
	flowCache := fastPath.hashMap[hash%HASH_MAP_SIZE]
	if flowCache == nil {
		flowCache = fastPath.createFlowCache(FLOW_CACHE_CAP, hash%HASH_MAP_SIZE)
	}
	flowCache.Lock()
	if flowExtra, reply = flowCache.keyMatch(meta, flowKey); flowExtra != nil {
		if flowExtra.updateFlow(meta, reply) {
			f.stats.CurrNumFlows--
			flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(false)
			flowExtra.setCurFlowInfo(meta.Timestamp, f.forceReportIntervalSec)
			flowExtra.calcCloseType(false)
			f.flowOutQueue.Put(flowExtra.taggedFlow)
			// delete front from this FlowCache because flowExtra is moved to front in keyMatch()
			flowCache.flowList.Remove(flowCache.flowList.Front())
		}
		info := flowExtra.initFlowInfo(flowExtra.taggedFlow, flowExtra.flowState, reply)
		flowExtra.metaFlowPerf.Update(meta, info)
	} else {
		var closed bool
		flowExtra, closed = f.initFlow(meta, flowKey)
		flowExtra.metaFlowPerf = NewMetaFlowPerf()
		f.stats.TotalNumFlows++
		if closed {
			flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(false)
			flowExtra.setCurFlowInfo(meta.Timestamp, f.forceReportIntervalSec)
			flowExtra.calcCloseType(false)
			f.flowOutQueue.Put(flowExtra.taggedFlow)
		} else {
			info := flowExtra.initFlowInfo(flowExtra.taggedFlow, flowExtra.flowState, false)
			flowExtra.metaFlowPerf.Update(meta, info)

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
	log.Info("FlowGen handler is running")
	for {
		meta := metaPacketHeaderInQueue.Get().(*handler.MetaPacket)
		if meta.Proto != layers.IPProtocolTCP {
			continue
		}
		f.processPacket(meta)
	}
}

func (f *FlowGenerator) cleanTimeoutHashMap(hashMap []*FlowCache, start, end uint64) {
	flowOutQueue := f.flowOutQueue
	forceReportIntervalSec := f.forceReportIntervalSec
	sleepDuration := f.minLoopIntervalSec * time.Second

loop:
	time.Sleep(sleepDuration)
	now := time.Duration(time.Now().UnixNano())
	nowSec := now / time.Second
	for _, flowCache := range hashMap[start:end] {
		if flowCache == nil {
			continue
		}
		flowCache.Lock()
		// FIXME: need to optimize the look-up, we can add the new updated flow to tail
		for e := flowCache.flowList.Front(); e != nil; {
			var del *list.Element = nil
			flowExtra := e.Value.(*FlowExtra)
			// FIXME: modify flow direction by port and service list
			if flowExtra.recentTimesSec+flowExtra.timeoutSec <= nowSec {
				del = e
				f.stats.CurrNumFlows--
				flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(false)
				flowExtra.setCurFlowInfo(now, forceReportIntervalSec)
				flowExtra.calcCloseType(false)
				flowOutQueue.Put(flowExtra.taggedFlow)
			} else if flowExtra.taggedFlow.StartTime/time.Second+forceReportIntervalSec < nowSec {
				flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report(false)
				flowExtra.setCurFlowInfo(now, forceReportIntervalSec)
				flowExtra.calcCloseType(true)
				flowExtra.tryForceReport(flowOutQueue)
				flowExtra.resetCurFlowInfo(now)
			}
			e = e.Next()
			if del != nil {
				flowCache.flowList.Remove(del)
			}
		}
		flowCache.Unlock()
	}
	goto loop
}

func (f *FlowGenerator) timeoutReport() {
	fastPath := &f.fastPath
	var num uint64
	if fastPath.size%fastPath.timeoutParallelNum != 0 {
		num = fastPath.size / (fastPath.timeoutParallelNum - 1)
	} else {
		num = fastPath.size / fastPath.timeoutParallelNum
	}
	for i := uint64(0); i < fastPath.timeoutParallelNum; i++ {
		start := i * num
		end := start + num
		if end <= fastPath.size {
			go f.cleanTimeoutHashMap(fastPath.hashMap, start, end)
			log.Debugf("clean goroutine %d (range %d to %d) created", i, start, end)
		} else {
			go f.cleanTimeoutHashMap(fastPath.hashMap, start, fastPath.size)
			log.Debugf("clean goroutine %d (range %d to %d) created", i, start, fastPath.size)
			break
		}
	}
}

func (f *FlowGenerator) run() {
	f.timeoutReport()
	go f.handle()
}

// we need these goroutines are thread safe
func (f *FlowGenerator) Start() {
	if !f.running {
		f.running = true
		f.run()
	}
}

func (f *FlowGenerator) Stop() {
	if f.running {
		f.running = false
	}
}

// create a new flow generator
func New(metaPacketHeaderInQueue QueueReader, flowOutQueue QueueWriter, forceReportIntervalSec time.Duration) *FlowGenerator {
	flowGenerator := &FlowGenerator{
		metaPacketHeaderInQueue: metaPacketHeaderInQueue,
		flowOutQueue:            flowOutQueue,
		fastPath:                FastPath{FlowCacheHashMap: FlowCacheHashMap{make([]*FlowCache, HASH_MAP_SIZE), HASH_MAP_SIZE, 4}},
		forceReportIntervalSec:  forceReportIntervalSec,
		minLoopIntervalSec:      5,
		flowLimitNum:            FLOW_LIMIT_NUM,
		running:                 false,
	}
	RegisterCountable("flow_gen", EMPTY_TAG, flowGenerator)
	log.Info("Flow Generator created")
	return flowGenerator
}
