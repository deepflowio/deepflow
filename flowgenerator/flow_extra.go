package flowgenerator

import (
	"time"

	"github.com/google/gopacket/layers"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type FlowState int32

const (
	FLOW_STATE_RAW FlowState = iota
	FLOW_STATE_OPENING_1
	FLOW_STATE_OPENING_2
	FLOW_STATE_ESTABLISHED
	FLOW_STATE_CLOSING_TX1
	FLOW_STATE_CLOSING_TX2
	FLOW_STATE_CLOSING_RX1
	FLOW_STATE_CLOSING_RX2
	FLOW_STATE_CLOSED
	FLOW_STATE_RESET
	FLOW_STATE_EXCEPTION

	FLOW_STATE_MAX
)

type FlowCOWFlag uint8

const (
	FLOW_COW_PACKET_STAT FlowCOWFlag = 1 << iota
	FLOW_COW_FLOW_STAT
)

type FlowExtra struct {
	taggedFlow   *TaggedFlow
	metaFlowPerf *MetaFlowPerf

	policyDataCache   [2]PolicyData
	endpointDataCache EndpointData

	minArrTime time.Duration
	recentTime time.Duration // 最近一个Packet的时间戳
	timeout    time.Duration // 相对超时时间
	flowState  FlowState
	reversed   bool

	packetInTick  bool // 当前包统计周期（目前是自然秒）是否有包
	packetInCycle bool // 当前流统计周期（目前是自然分）是否有包

	cow FlowCOWFlag // 标记下次改写内容前是否需要拷贝
}

func macMatch(meta *MetaPacket, flowMacSrc, flowMacDst MacInt, matchType int) bool {
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

func tunnelMatch(metaTunnelInfo, flowTunnelInfo *TunnelInfo) bool {
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

func (e *FlowExtra) keyMatchForEthOthers(meta *MetaPacket) bool {
	taggedFlow := e.taggedFlow
	flowMacSrc, flowMacDst := taggedFlow.MACSrc, taggedFlow.MACDst
	if flowMacSrc == meta.MacSrc && flowMacDst == meta.MacDst {
		meta.Direction = CLIENT_TO_SERVER
		return true
	}
	if flowMacSrc == meta.MacDst && flowMacDst == meta.MacSrc {
		meta.Direction = SERVER_TO_CLIENT
		return true
	}

	return false
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

func (e *FlowExtra) Match(meta *MetaPacket) bool {
	if meta.EthType != layers.EthernetTypeIPv4 && meta.EthType != layers.EthernetTypeIPv6 {
		return e.keyMatchForEthOthers(meta)
	}
	taggedFlow := e.taggedFlow
	if taggedFlow.VtapId != meta.VtapId || meta.InPort != taggedFlow.InPort {
		return false
	}
	macMatchType := requireMacMatch(meta, ignoreTorMac, ignoreL2End)
	if macMatchType != MAC_MATCH_NONE && !macMatch(meta, taggedFlow.MACSrc, taggedFlow.MACDst, macMatchType) {
		return false
	}
	if taggedFlow.EthType != meta.EthType {
		return false
	}
	if taggedFlow.Proto != meta.Protocol || !tunnelMatch(meta.Tunnel, &taggedFlow.TunnelInfo) {
		return false
	}
	flowPortSrc, flowPortDst := taggedFlow.PortSrc, taggedFlow.PortDst
	metaPortSrc, metaPortDst := meta.PortSrc, meta.PortDst
	if meta.EthType == layers.EthernetTypeIPv4 {
		flowIPSrc, flowIPDst := taggedFlow.IPSrc, taggedFlow.IPDst
		metaIpSrc, metaIpDst := meta.IpSrc, meta.IpDst
		if flowIPSrc == metaIpSrc && flowIPDst == metaIpDst && flowPortSrc == metaPortSrc && flowPortDst == metaPortDst {
			meta.Direction = CLIENT_TO_SERVER
			return true
		} else if flowIPSrc == metaIpDst && flowIPDst == metaIpSrc && flowPortSrc == metaPortDst && flowPortDst == metaPortSrc {
			meta.Direction = SERVER_TO_CLIENT
			return true
		}
	} else {
		flowIP6Src, flowIP6Dst := taggedFlow.IP6Src, taggedFlow.IP6Dst
		metaIp6Src, metaIp6Dst := meta.Ip6Src, meta.Ip6Dst
		if flowIP6Src.Equal(metaIp6Src) && flowIP6Dst.Equal(metaIp6Dst) && flowPortSrc == metaPortSrc && flowPortDst == metaPortDst {
			meta.Direction = CLIENT_TO_SERVER
			return true
		} else if flowIP6Src.Equal(metaIp6Dst) && flowIP6Dst.Equal(metaIp6Src) && flowPortSrc == metaPortDst && flowPortDst == metaPortSrc {
			meta.Direction = SERVER_TO_CLIENT
			return true
		}
	}
	return false
}

func (f *FlowExtra) setEndTimeAndDuration(timestamp time.Duration) {
	taggedFlow := f.taggedFlow
	taggedFlow.EndTime = timestamp
	taggedFlow.Duration = f.recentTime - f.minArrTime // Duration仅使用包的时间计算，不包括超时时间
}

func (f *FlowExtra) resetPacketStatInfo() {
	f.packetInTick = false
	taggedFlow := f.taggedFlow
	taggedFlow.PacketStatTime = 0
	flowMetricsPeerSrc := &taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST]
	flowMetricsPeerSrc.TickPacketCount = 0
	flowMetricsPeerDst.TickPacketCount = 0
	flowMetricsPeerSrc.TickByteCount = 0
	flowMetricsPeerDst.TickByteCount = 0
}

func (f *FlowExtra) resetFlowStatInfo() {
	f.packetInCycle = false
	taggedFlow := f.taggedFlow
	taggedFlow.TimeBitmap = 0
	taggedFlow.FlowStatTime += _FLOW_STAT_INTERVAL
	taggedFlow.StartTime = taggedFlow.FlowStatTime
	taggedFlow.EndTime = taggedFlow.FlowStatTime
	taggedFlow.IsNewFlow = false
	flowMetricsPeerSrc := &taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &taggedFlow.FlowMetricsPeers[FLOW_METRICS_PEER_DST]
	flowMetricsPeerSrc.PacketCount = 0
	flowMetricsPeerDst.PacketCount = 0
	flowMetricsPeerSrc.ByteCount = 0
	flowMetricsPeerDst.ByteCount = 0
}
