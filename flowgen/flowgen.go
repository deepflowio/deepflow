package flowgen

import (
	"container/list"
	"encoding/binary"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	. "gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"

	"gitlab.x.lan/yunshan/droplet/flowperf"
	"gitlab.x.lan/yunshan/droplet/handler"
)

var log = logging.MustGetLogger("flowgen")

func getFlowKey(header *handler.MetaPacketHeader) *FlowKey {
	flowKey := &FlowKey{
		Exporter: *NewIPFromInt(binary.BigEndian.Uint32(header.Exporter.To4())),
		IPSrc:    *NewIPFromInt(binary.BigEndian.Uint32(header.IpSrc.To4())),
		IPDst:    *NewIPFromInt(binary.BigEndian.Uint32(header.IpDst.To4())),
		Proto:    header.Proto,
		PortSrc:  header.PortSrc,
		PortDst:  header.PortDst,
		InPort0:  header.InPort,
	}

	if header.TunnelData.TunnelType != handler.TUNNEL_TYPE_NONE {
		flowKey.TunnelType = uint8(header.TunnelData.TunnelType)
		flowKey.TunnelID = header.TunnelData.TunnelId
		flowKey.TunnelIPSrc = binary.BigEndian.Uint32(header.TunnelData.TunnelSrc.To4())
		flowKey.TunnelIPDst = binary.BigEndian.Uint32(header.TunnelData.TunnelDst.To4())
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

func (f *FlowExtra) MacEquals(header *handler.MetaPacketHeader) bool {
	taggedFlow := f.taggedFlow
	flowMacSrc, flowMacDst := taggedFlow.MACSrc.Int(), taggedFlow.MACDst.Int()
	metaPktHdrMacSrc, metaPktHdrMacDst := Mac2Uint64(header.MacSrc), Mac2Uint64(header.MacDst)
	if flowMacSrc == metaPktHdrMacSrc && flowMacDst == metaPktHdrMacDst {
		return true
	}
	if flowMacSrc == metaPktHdrMacDst && flowMacDst == metaPktHdrMacSrc {
		return true
	}
	return false
}

// FIXME: need a fast way to compare like memcmp
func (f *FlowCache) keyMatch(header *handler.MetaPacketHeader, key *FlowKey) (*FlowExtra, bool) {
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
		if isFromTrident(key) && !flowExtra.MacEquals(header) {
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

// FIXME: needs more info
func (f *FlowGenerator) genFlowId(timestamp uint64, inPort uint64) uint64 {
	return ((inPort & IN_PORT_FLOW_ID_MASK) << 32) | ((timestamp & TIMER_FLOW_ID_MASK) << 32) | (f.stats.TotalNumFlows & TOTAL_FLOWS_ID_MASK)
}

func (f *FlowGenerator) initFlow(header *handler.MetaPacketHeader, key *FlowKey) (*FlowExtra, bool) {
	now := time.Duration(header.Timestamp)
	taggedFlow := &TaggedFlow{
		Flow: Flow{
			FlowKey:           *key,
			FlowID:            f.genFlowId(uint64(now), uint64(key.InPort0)),
			StartTime:         now,
			EndTime:           now,
			CurStartTime:      now,
			ArrTime00:         now,
			ArrTime0Last:      now,
			MACSrc:            *NewMACAddrFromString(header.MacSrc.String()),
			MACDst:            *NewMACAddrFromString(header.MacDst.String()),
			VLAN:              header.Vlan,
			EthType:           header.EthType,
			CloseType:         CLOSE_TYPE_UNKNOWN,
			TotalPacketCount0: 1,
			PacketCount0:      1,
			TotalByteCount0:   uint64(header.PacketLen),
			ByteCount0:        uint64(header.PacketLen),
			IsL2End0:          header.L2End0,
			IsL2End1:          header.L2End1,
		},
		Tag: Tag{
			GroupIDs0: make([]uint32, 10),
			GroupIDs1: make([]uint32, 10),
		},
	}
	flowExtra := &FlowExtra{
		taggedFlow:     taggedFlow,
		flowState:      FLOW_STATE_EXCEPTION,
		recentTimesSec: now / time.Millisecond,
	}
	flowExtra.updatePlatformData(header)

	return flowExtra, flowExtra.updateTCPStateMachine(header.TcpData.Flags, false)
}

// it is a very simple implementation of TCP State machine
// just including judgements of rst, fin and syn
func (f *FlowExtra) updateTCPStateMachine(flags uint8, reply bool) bool {
	taggedFlow := f.taggedFlow
	if reply {
		taggedFlow.TCPFlags1 |= uint16(flags)
	} else {
		taggedFlow.TCPFlags0 |= uint16(flags)
	}

	if flags&TCP_RST > 0 {
		if f.flowState == FLOW_STATE_ESTABLISHED || taggedFlow.TotalPacketCount0 == 1 {
			f.timeoutSec = innerTimeoutConfig.EstablishedRst
		}
		f.flowState = FLOW_STATE_CLOSED
		return true
	}
	if flags&TCP_FIN > 0 {
		// FIXME: only with two fin flags can this flow be closed
		if taggedFlow.TCPFlags0&taggedFlow.TCPFlags1&TCP_FIN > 0 {
			f.flowState = FLOW_STATE_CLOSED
			f.timeoutSec = innerTimeoutConfig.ClosedFin
			return true
		}
		f.flowState = FLOW_STATE_CLOSING
		f.timeoutSec = innerTimeoutConfig.Closing
		return false
	}
	if flags&TCP_SYN > 0 || flags&TCP_ACK > 0 {
		// FIXME: only with two syn flags and ack flags can this flow be established
		if taggedFlow.TCPFlags0&taggedFlow.TCPFlags1&TCP_SYN > 0 &&
			taggedFlow.TCPFlags0&taggedFlow.TCPFlags1&TCP_ACK > 0 {
			f.flowState = FLOW_STATE_ESTABLISHED
			f.timeoutSec = innerTimeoutConfig.Established
			return false
		}
		if f.flowState == FLOW_STATE_EXCEPTION || f.flowState == FLOW_STATE_OPENING {
			f.flowState = FLOW_STATE_OPENING
			f.timeoutSec = innerTimeoutConfig.Opening
		}
		return false
	}

	return false
}

func (f *FlowExtra) updatePlatformData(header *handler.MetaPacketHeader) {
	endPointData := header.EndPointData
	if endPointData == nil {
		return
	}
	taggedFlow := f.taggedFlow
	srcInfo := endPointData.SrcInfo
	dstInfo := endPointData.DstInfo
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
		// FIXME: not to grow the size of GroupIDs
		copy(taggedFlow.GroupIDs1, srcInfo.GroupIds)
	}
}

// FIXME: should update more info
func (f *FlowExtra) updateFlow(header *handler.MetaPacketHeader, reply bool) bool {
	taggedFlow := f.taggedFlow
	bytes := uint64(header.PacketLen)
	packetTimestamp := time.Duration(header.Timestamp)
	if taggedFlow.StartTime != 0 && packetTimestamp > taggedFlow.StartTime {
		taggedFlow.EndTime = packetTimestamp
		taggedFlow.Duration = packetTimestamp - taggedFlow.StartTime
	} else {
		taggedFlow.Duration = 0
	}
	if reply {
		if taggedFlow.TotalPacketCount1 == 0 {
			taggedFlow.ArrTime10 = packetTimestamp
		}
		taggedFlow.ArrTime1Last = packetTimestamp
		taggedFlow.PacketCount1++
		taggedFlow.TotalPacketCount1++
		taggedFlow.ByteCount1 += bytes
		taggedFlow.TotalByteCount1 += bytes
	} else {
		taggedFlow.ArrTime0Last = packetTimestamp
		taggedFlow.PacketCount0++
		taggedFlow.TotalPacketCount0++
		taggedFlow.ByteCount0 += bytes
		taggedFlow.TotalByteCount0 += bytes
	}
	f.recentTimesSec = packetTimestamp / time.Millisecond
	f.updatePlatformData(header)

	return f.updateTCPStateMachine(header.TcpData.Flags, reply)
}

func (f *FlowExtra) checkTimeout(nowSec time.Duration) bool {
	if f.recentTimesSec+f.timeoutSec <= nowSec {
		return true
	}
	return false
}

func (f *FlowExtra) calcCloseType() {
	switch f.timeoutSec + time.Duration(f.flowState) {
	case innerTimeoutConfig.Opening + FLOW_STATE_OPENING:
		f.taggedFlow.CloseType = CLOSE_TYPE_HALF_OPEN
	case innerTimeoutConfig.Established + FLOW_STATE_ESTABLISHED:
		f.taggedFlow.CloseType = CLOSE_TYPE_FORCE_REPORT
	case innerTimeoutConfig.Closing + FLOW_STATE_CLOSING:
		f.taggedFlow.CloseType = CLOSE_TYPE_HALF_CLOSE
	case innerTimeoutConfig.ClosedFin + FLOW_STATE_CLOSED:
		f.taggedFlow.CloseType = CLOSE_TYPE_FIN
	case innerTimeoutConfig.EstablishedRst + FLOW_STATE_CLOSED:
		f.taggedFlow.CloseType = CLOSE_TYPE_RST
	default:
		if f.taggedFlow.TCPFlags0|f.taggedFlow.TCPFlags1&TCP_RST > 0 {
			f.taggedFlow.CloseType = CLOSE_TYPE_RST
		}
	}
}

func (f *FlowGenerator) processPacket(header *handler.MetaPacketHeader) {
	reply := false
	var flowExtra *FlowExtra
	fastPath := &f.fastPath
	flowKey := getFlowKey(header)
	hash := getQuinTupleHash(flowKey)
	flowCache := fastPath.hashMap[hash%HASH_MAP_SIZE]
	if flowCache == nil {
		flowCache = fastPath.createFlowCache(FLOW_CACHE_CAP, hash%HASH_MAP_SIZE)
	}
	flowCache.Lock()
	if flowExtra, reply = flowCache.keyMatch(header, flowKey); flowExtra != nil {
		flowExtra.metaFlowPerf.Update(header, reply)

		if flowExtra.updateFlow(header, reply) {
			f.stats.CurrNumFlows--
			flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report()
			flowExtra.calcCloseType()
			f.flowOutQueue.Put(flowExtra.taggedFlow)
			// delete front from this FlowCache because flowExtra is moved to front in keyMatch()
			flowCache.flowList.Remove(flowCache.flowList.Front())
		}
	} else {
		var closed bool
		flowExtra, closed = f.initFlow(header, flowKey)
		flowExtra.metaFlowPerf = flowperf.NewMetaFlowPerf()
		flowExtra.metaFlowPerf.Update(header, reply)
		f.stats.TotalNumFlows++
		if closed {
			flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report()
			flowExtra.calcCloseType()
			f.flowOutQueue.Put(flowExtra.taggedFlow)
		} else {
			if flowExtra == f.addFlow(flowCache, flowExtra) {
				// reach limit and output directly
				flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report()
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
		header := metaPacketHeaderInQueue.Get().(*handler.MetaPacketHeader)
		if header.Proto != layers.IPProtocolTCP {
			continue
		}
		f.processPacket(header)
	}
}

func (f *FlowGenerator) cleanTimeoutHashMap(hashMap []*FlowCache, start, end uint64) {
	flowOutQueue := f.flowOutQueue
	forceReportIntervalSec := f.forceReportIntervalSec
	minLoopIntervalSec := f.minLoopIntervalSec

loop:
	time.Sleep(minLoopIntervalSec * time.Second)
	now := time.Duration(time.Now().UnixNano()) / time.Microsecond
	nowSec := time.Duration(now / time.Millisecond)
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
				flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report()
				flowExtra.calcCloseType()
				flowOutQueue.Put(flowExtra.taggedFlow)
			} else if flowExtra.recentTimesSec+forceReportIntervalSec < nowSec {
				flowExtra.taggedFlow.TcpPerfStats = flowExtra.metaFlowPerf.Report()
				flowExtra.calcCloseType()
				taggedFlow := *flowExtra.taggedFlow
				taggedFlow.EndTime = now
				flowOutQueue.Put(&taggedFlow)
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
	num := fastPath.size / fastPath.timeoutParallelNum
	for i := uint64(0); i < fastPath.timeoutParallelNum; i += num {
		go f.cleanTimeoutHashMap(fastPath.hashMap, i, i+num)
	}
}

// we need these goroutines are thread safe
func (f *FlowGenerator) Start() {
	f.timeoutReport()
	go f.handle()
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
	}
	RegisterCountable("flow_gen", EMPTY_TAG, flowGenerator)
	log.Info("Flow Generator created")
	return flowGenerator
}
