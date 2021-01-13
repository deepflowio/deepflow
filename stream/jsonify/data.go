package jsonify

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/grpc"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/droplet-libs/zerodoc"
	"gitlab.x.lan/yunshan/droplet/stream/geo"
	pf "gitlab.x.lan/yunshan/droplet/stream/platformdata"
)

type FlowLogger struct {
	DataLinkLayer
	NetworkLayer
	TransportLayer
	ApplicationLayer
	Internet
	KnowledgeGraph
	FlowInfo
	Metrics
}

type DataLinkLayer struct {
	MAC0         string   `json:"mac_0"`
	MAC1         string   `json:"mac_1"`
	EthType      uint16   `json:"eth_type"`
	CastTypes0   []string `json:"cast_types_0"`
	CastTypes1   []string `json:"cast_types_1"`
	PacketSizes0 []string `json:"packet_sizes_0"`
	PacketSizes1 []string `json:"packet_sizes_1"`
	VLAN         uint16   `json:"vlan,omitempty"`
}

type NetworkLayer struct {
	IP0         string   `json:"ip_0"` // 广域网IP为0.0.0.0或::
	IP1         string   `json:"ip_1"`
	RealIP0     string   `json:"real_ip_0"`
	RealIP1     string   `json:"real_ip_1"`
	IPVersion   uint16   `json:"ip_version,omitempty"`
	Protocol    uint16   `json:"protocol"`
	TunnelTier  uint8    `json:"tunnel_tier,omitempty"`
	TunnelType  uint16   `json:"tunnel_type,omitempty"`
	TunnelTxID  uint32   `json:"tunnel_tx_id,omitempty"`
	TunnelRxID  uint32   `json:"tunnel_rx_id,omitempty"`
	TunnelTxIP0 string   `json:"tunnel_tx_ip_0,omitempty"`
	TunnelTxIP1 string   `json:"tunnel_tx_ip_1,omitempty"`
	TunnelRxIP0 string   `json:"tunnel_rx_ip_0,omitempty"`
	TunnelRxIP1 string   `json:"tunnel_rx_ip_1,omitempty"`
	TTLs0       []string `json:"ttls_0"`
	TTLs1       []string `json:"ttls_1"`
}

type TransportLayer struct {
	ClientPort   uint16   `json:"client_port,omitempty"`
	ServerPort   uint16   `json:"server_port,omitempty"`
	TCPFlags0    []uint16 `json:"tcp_flags_0"`
	TCPFlags1    []uint16 `json:"tcp_flags_1"`
	TCPFlagsBit0 uint16   `json:"tcp_flags_bit_0,omitempty"`
	TCPFlagsBit1 uint16   `json:"tcp_flags_bit_1,omitempty"`
}

type ApplicationLayer struct {
	L7Protocol string `json:"l7_protocol,omitempty"` // HTTP, DNS, others
}

type Internet struct {
	Province0 string `json:"province_0"`
	Province1 string `json:"province_1"`
}

type KnowledgeGraph struct {
	RegionID0     uint32 `json:"region_id_0"`
	RegionID1     uint32 `json:"region_id_1"`
	AZID0         uint32 `json:"az_id_0"`
	AZID1         uint32 `json:"az_id_1"`
	HostID0       uint32 `json:"host_id_0"`
	HostID1       uint32 `json:"host_id_1"`
	L3DeviceType0 uint32 `json:"l3_device_type_0"`
	L3DeviceType1 uint32 `json:"l3_device_type_1"`
	L3DeviceID0   uint32 `json:"l3_device_id_0"`
	L3DeviceID1   uint32 `json:"l3_device_id_1"`
	PodNodeID0    uint32 `json:"pod_node_id_0"`
	PodNodeID1    uint32 `json:"pod_node_id_1"`
	PodNSID0      uint32 `json:"pod_ns_id_0"`
	PodNSID1      uint32 `json:"pod_ns_id_1"`
	PodGroupID0   uint32 `json:"pod_group_id_0"`
	PodGroupID1   uint32 `json:"pod_group_id_1"`
	PodID0        uint32 `json:"pod_id_0"`
	PodID1        uint32 `json:"pod_id_1"`
	PodClusterID0 uint32 `json:"pod_cluster_id_0"`
	PodClusterID1 uint32 `json:"pod_cluster_id_1"`
	L3EpcID0      int32  `json:"l3_epc_id_0"`
	L3EpcID1      int32  `json:"l3_epc_id_1"`
	EpcID0        int32  `json:"epc_id_0"`
	EpcID1        int32  `json:"epc_id_1"`
	SubnetID0     uint32 `json:"subnet_id_0"`
	SubnetID1     uint32 `json:"subnet_id_1"`
}

type FlowInfo struct {
	CloseType  uint16 `json:"close_type"`
	FlowSource uint16 `json:"flow_source"`
	FlowIDStr  string `json:"flow_id_str"`
	TapType    uint16 `json:"tap_type"`
	TapPort    string `json:"tap_port"` // 显示为0x+固定八个字符的16进制如0x01234567
	VtapID     uint16 `json:"vtap_id"`
	TapSide0   bool   `json:"tap_side_0,omitempty"`
	TapSide1   bool   `json:"tap_side_1,omitempty"`
	L2End0     bool   `json:"l2_end_0"`
	L2End1     bool   `json:"l2_end_1"`
	L3End0     bool   `json:"l3_end_0"`
	L3End1     bool   `json:"l3_end_1"`
	StartTime  uint64 `json:"start_time"` // s
	EndTime    uint64 `json:"end_time"`   // s
	Duration   uint64 `json:"duration"`   // us
}

type Metrics struct {
	PacketTx        uint64 `json:"packet_tx,omitempty"`
	PacketRx        uint64 `json:"packet_rx,omitempty"`
	ByteTx          uint64 `json:"byte_tx,omitempty"`
	ByteRx          uint64 `json:"byte_rx,omitempty"`
	L3ByteTx        uint64 `json:"l3_byte_tx,omitempty"`
	L3ByteRx        uint64 `json:"l3_byte_rx,omitempty"`
	L4ByteTx        uint64 `json:"l4_byte_tx,omitempty"`
	L4ByteRx        uint64 `json:"l4_byte_rx,omitempty"`
	TotalPacketTx   uint64 `json:"total_packet_tx,omitempty"`
	TotalPacketRx   uint64 `json:"total_packet_rx,omitempty"`
	TotalByteTx     uint64 `json:"total_byte_tx,omitempty"`
	TotalByteRx     uint64 `json:"total_byte_rx,omitempty"`
	L7Request       uint32 `json:"l7_request,omitempty"`
	L7Response      uint32 `json:"l7_response,omitempty"`
	RTTClient       uint32 `json:"rtt_client,omitempty"` // us
	RTTServer       uint32 `json:"rtt_server,omitempty"` // us
	RTT             uint32 `json:"rtt,omitempty"`        // us
	SRT             uint32 `json:"srt,omitempty"`        // us
	ART             uint32 `json:"art,omitempty"`        // us
	RRT             uint32 `json:"rrt,omitempty"`        // us
	RetransTx       uint32 `json:"retrans_tx,omitempty"`
	RetransRx       uint32 `json:"retrans_rx,omitempty"`
	ZeroWinTx       uint32 `json:"zero_win_tx,omitempty"`
	ZeroWinRx       uint32 `json:"zero_win_rx,omitempty"`
	L7ClientError   uint32 `json:"l7_client_error,omitempty"`
	L7ServerError   uint32 `json:"l7_server_error,omitempty"`
	L7ServerTimeout uint32 `json:"l7_server_timeout,omitempty"`
}

func parseUint32EpcID(v uint32) int32 {
	switch int16(v) {
	case datatype.EPC_FROM_DEEPFLOW:
		fallthrough
	case datatype.EPC_FROM_INTERNET:
		return int32(int16(v))
	}
	return int32(math.MaxUint16 & v)
}

func castTypeToString(castType uint8) string {
	switch zerodoc.CastTypeEnum(castType) {
	case zerodoc.BROADCAST:
		return "broadcast"
	case zerodoc.MULTICAST:
		return "multicast"
	case zerodoc.UNICAST:
		return "unicast"
	default:
		return "unknown"
	}

}

func getCastTypes(castTypeMap uint8, castTypes []string) []string {
	// 不记录zerodoc.UNKNOWN(已知单播)
	for i := int(zerodoc.UNKNOWN) + 1; i < int(zerodoc.MAX_CAST_TYPE); i++ {
		castType := castTypeMap & (1 << i)
		if castType != 0 {
			castTypes = append(castTypes, castTypeToString(uint8(i)))
		}
	}
	return castTypes
}

func getPacketSizes(packetSizeMap uint16, packetSizes []string) []string {
	for i := 0; i < int(zerodoc.MAX_PACKET_SIZE-zerodoc.PACKET_SIZE_0_64); i++ {
		if packetSizeMap&(1<<i) != 0 {
			packetSizes = append(packetSizes, zerodoc.TTL_PACKET_SIZE[i+int(zerodoc.PACKET_SIZE_0_64)])
		}
	}
	return packetSizes
}

func getTTLs(TTLMap uint16, TTLs []string) []string {
	for i := 0; i < int(zerodoc.MAX_TTL-zerodoc.TTL_1); i++ {
		if TTLMap&(1<<i) != 0 {
			TTLs = append(TTLs, zerodoc.TTL_PACKET_SIZE[i+int(zerodoc.TTL_1)])
		}
	}
	return TTLs
}
func getTCPFlags(TCPFlagsMap uint16, TCPFlags []uint16) []uint16 {
	for i := 0; i < int(zerodoc.MAX_TCP_FLAGS_INDEX-zerodoc.TCP_FLAG_SYN_INDEX); i++ {
		if TCPFlagsMap&(1<<i) != 0 {
			TCPFlags = append(TCPFlags, uint16(zerodoc.TCPIndexToFlags[i+int(zerodoc.TCP_FLAG_SYN_INDEX)]))
		}
	}
	return TCPFlags

}

func (d *DataLinkLayer) Fill(f *datatype.TaggedFlow) {
	d.MAC0 = utils.Uint64ToMac(f.MACSrc).String()
	d.MAC1 = utils.Uint64ToMac(f.MACDst).String()
	d.EthType = uint16(f.EthType)
	d.CastTypes0 = getCastTypes(f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].CastTypeMap, d.CastTypes0)
	d.CastTypes1 = getCastTypes(f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].CastTypeMap, d.CastTypes1)
	d.PacketSizes0 = getPacketSizes(f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].PacketSizeMap, d.PacketSizes0)
	d.PacketSizes1 = getPacketSizes(f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].PacketSizeMap, d.PacketSizes1)
	d.VLAN = f.VLAN
}

func (n *NetworkLayer) Fill(f *datatype.TaggedFlow, isIPV6 bool) {
	// 广域网IP为0.0.0.0或::
	if isIPV6 {
		n.IPVersion = 6
		if datatype.EPC_FROM_INTERNET == f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].L3EpcID {
			n.IP0 = "::"
		} else {
			n.IP0 = f.IP6Src.String()
		}
		if datatype.EPC_FROM_INTERNET == f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].L3EpcID {
			n.IP1 = "::"
		} else {
			n.IP1 = f.IP6Dst.String()
		}
		n.RealIP0 = f.IP6Src.String()
		n.RealIP1 = f.IP6Dst.String()
	} else {
		n.IPVersion = 4
		if datatype.EPC_FROM_INTERNET == f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].L3EpcID {
			n.IP0 = "0.0.0.0"
		} else {
			n.IP0 = IPIntToString(uint32(f.IPSrc))
		}
		if datatype.EPC_FROM_INTERNET == f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].L3EpcID {
			n.IP1 = "0.0.0.0"
		} else {
			n.IP1 = IPIntToString(uint32(f.IPDst))
		}
		n.RealIP0 = IPIntToString(uint32(f.IPSrc))
		n.RealIP1 = IPIntToString(uint32(f.IPDst))
	}

	n.Protocol = uint16(f.Proto)
	if f.Tunnel.TxId != 0 || f.Tunnel.RxId != 0 {
		n.TunnelTier = f.Tunnel.Tier
		n.TunnelTxID = f.Tunnel.TxId
		n.TunnelRxID = f.Tunnel.RxId
		n.TunnelType = uint16(f.Tunnel.Type)
		n.TunnelTxIP0 = IPIntToString(f.Tunnel.TxIP0)
		n.TunnelTxIP1 = IPIntToString(f.Tunnel.TxIP1)
		n.TunnelRxIP0 = IPIntToString(f.Tunnel.RxIP0)
		n.TunnelRxIP1 = IPIntToString(f.Tunnel.RxIP1)
	}
	n.TTLs0 = getTTLs(f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].TTLMap, n.TTLs0)
	n.TTLs1 = getTTLs(f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].TTLMap, n.TTLs1)
}

func (t *TransportLayer) Fill(f *datatype.TaggedFlow) {
	t.ClientPort = f.PortSrc
	t.ServerPort = f.PortDst
	t.TCPFlagsBit0 = uint16(f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].TCPFlags)
	t.TCPFlagsBit1 = uint16(f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].TCPFlags)

	t.TCPFlags0 = getTCPFlags(f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].TCPFlagsMap, t.TCPFlags0)
	t.TCPFlags1 = getTCPFlags(f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].TCPFlagsMap, t.TCPFlags1)
}

func (a *ApplicationLayer) Fill(f *datatype.TaggedFlow) {
	a.L7Protocol = "others" // HTTP, DNS, others
	if f.FlowPerfStats != nil {
		if f.FlowPerfStats.L7Protocol == datatype.L7_PROTOCOL_HTTP {
			a.L7Protocol = "HTTP"
		} else if f.FlowPerfStats.L7Protocol == datatype.L7_PROTOCOL_DNS {
			a.L7Protocol = "DNS"
		}
	}
}

func (i *Internet) Fill(f *datatype.TaggedFlow) {
	i.Province0 = geo.QueryProvince(f.IPSrc)
	i.Province1 = geo.QueryProvince(f.IPDst)
}

func (k *KnowledgeGraph) Fill(f *datatype.TaggedFlow, isIPV6 bool) {
	var info0, info1 *grpc.Info
	l3EpcID0, l3EpcID1 := f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].L3EpcID, f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].L3EpcID
	isVip0, isVip1 := f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].IsVIPInterface, f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].IsVIPInterface
	mac0, mac1 := f.FlowKey.MACSrc, f.FlowKey.MACDst
	l3EpcMac0, l3EpcMac1 := mac0|uint64(l3EpcID0)<<48, mac1|uint64(l3EpcID1)<<48 // 使用l3EpcID和mac查找，防止跨AZ mac冲突

	if isVip0 && isVip1 {
		info0, info1 = pf.PlatformData.QueryMacInfosPair(l3EpcMac0, l3EpcMac1)
	} else if isVip0 {
		info0 = pf.PlatformData.QueryMacInfo(l3EpcMac0)
		if isIPV6 {
			info1 = pf.PlatformData.QueryIPV6Infos(int16(l3EpcID1), f.IP6Dst)
		} else {
			info1 = pf.PlatformData.QueryIPV4Infos(int16(l3EpcID1), uint32(f.IPDst))
		}
	} else if isVip1 {
		if isIPV6 {
			info0 = pf.PlatformData.QueryIPV6Infos(int16(l3EpcID0), f.IP6Src)
		} else {
			info0 = pf.PlatformData.QueryIPV4Infos(int16(l3EpcID0), uint32(f.IPSrc))
		}
		info1 = pf.PlatformData.QueryMacInfo(l3EpcMac1)
	} else if isIPV6 {
		info0, info1 = pf.PlatformData.QueryIPV6InfosPair(int16(l3EpcID0), f.IP6Src, int16(l3EpcID1), f.IP6Dst)
	} else {
		info0, info1 = pf.PlatformData.QueryIPV4InfosPair(int16(l3EpcID0), uint32(f.IPSrc), int16(l3EpcID1), uint32(f.IPDst))
	}

	var l2Info0, l2Info1 *grpc.Info
	if l3EpcID0 > 0 && l3EpcID1 > 0 {
		l2Info0, l2Info1 = pf.PlatformData.QueryMacInfosPair(l3EpcMac0, l3EpcMac1)
	} else if l3EpcID0 > 0 {
		l2Info0 = pf.PlatformData.QueryMacInfo(l3EpcMac0)
	} else if l3EpcID1 > 0 {
		l2Info1 = pf.PlatformData.QueryMacInfo(l3EpcMac1)
	}

	if info0 != nil {
		k.RegionID0 = info0.RegionID
		k.AZID0 = info0.AZID
		k.HostID0 = info0.HostID
		k.L3DeviceType0 = info0.DeviceType
		k.L3DeviceID0 = info0.DeviceID
		k.PodNodeID0 = info0.PodNodeID
		k.PodNSID0 = info0.PodNSID
		k.PodGroupID0 = info0.PodGroupID
		k.PodID0 = info0.PodID
		k.PodClusterID0 = info0.PodClusterID
		k.SubnetID0 = info0.SubnetID
	}
	if info1 != nil {
		k.RegionID1 = info1.RegionID
		k.AZID1 = info1.AZID
		k.HostID1 = info1.HostID
		k.L3DeviceType1 = info1.DeviceType
		k.L3DeviceID1 = info1.DeviceID
		k.PodNodeID1 = info1.PodNodeID
		k.PodNSID1 = info1.PodNSID
		k.PodGroupID1 = info1.PodGroupID
		k.PodID1 = info1.PodID
		k.PodClusterID1 = info1.PodClusterID
		k.SubnetID1 = info1.SubnetID
	}
	k.L3EpcID0, k.L3EpcID1 = l3EpcID0, l3EpcID1
	if l2Info0 != nil {
		k.EpcID0 = parseUint32EpcID(l2Info0.L2EpcID)
	}
	if l2Info1 != nil {
		k.EpcID1 = parseUint32EpcID(l2Info1.L2EpcID)
	}
}

func (i *FlowInfo) Fill(f *datatype.TaggedFlow) {
	i.CloseType = uint16(f.CloseType)
	i.FlowSource = uint16(f.FlowSource)
	i.FlowIDStr = strconv.FormatInt(int64(f.FlowID), 10)
	i.TapType = uint16(f.TapType)
	i.TapPort = fmt.Sprintf("0x%08x", f.TapPort)
	i.VtapID = f.VtapId

	i.L2End0 = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].IsL2End
	i.L2End1 = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].IsL2End
	i.L3End0 = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].IsL3End
	i.L3End1 = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].IsL3End

	i.StartTime = uint64(f.StartTime / time.Second)
	i.EndTime = uint64(f.EndTime / time.Second)
	i.Duration = uint64(f.Duration / time.Microsecond)
}

func (m *Metrics) Fill(f *datatype.TaggedFlow) {
	m.PacketTx = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].PacketCount
	m.PacketRx = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].PacketCount
	m.ByteTx = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].ByteCount
	m.ByteRx = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].ByteCount
	m.L3ByteTx = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].L3ByteCount
	m.L3ByteRx = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].L3ByteCount
	m.L4ByteTx = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].L4ByteCount
	m.L4ByteRx = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].L4ByteCount

	m.TotalPacketTx = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].TotalPacketCount
	m.TotalPacketRx = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].TotalPacketCount
	m.TotalByteTx = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].TotalByteCount
	m.TotalByteRx = f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].TotalByteCount

	if f.FlowPerfStats != nil {
		m.L7Request = f.L7PerfStats.RequestCount
		m.L7Response = f.L7PerfStats.ResponseCount
		m.L7ClientError = f.L7PerfStats.ErrClientCount
		m.L7ServerError = f.L7PerfStats.ErrServerCount
		m.L7ServerTimeout = f.L7PerfStats.ErrTimeout

		if f.TCPPerfStats.RTTClientCount != 0 {
			m.RTTClient = f.TCPPerfStats.RTTClientSum / f.TCPPerfStats.RTTClientCount
		}
		if f.TCPPerfStats.RTTServerCount != 0 {
			m.RTTServer = f.TCPPerfStats.RTTServerSum / f.TCPPerfStats.RTTServerCount
		}

		if f.TCPPerfStats.RTTCount != 0 {
			m.RTT = f.TCPPerfStats.RTTSum / f.TCPPerfStats.RTTCount
		}
		if f.TCPPerfStats.SRTCount != 0 {
			m.SRT = f.TCPPerfStats.SRTSum / f.TCPPerfStats.SRTCount
		}
		if f.TCPPerfStats.ARTCount != 0 {
			m.ART = f.TCPPerfStats.ARTSum / f.TCPPerfStats.ARTCount
		}
		if f.L7PerfStats.RRTCount != 0 {
			m.RRT = f.L7PerfStats.RRTSum / f.L7PerfStats.RRTCount
		}

		m.RetransTx = f.TCPPerfStats.TcpPerfCountsPeers[0].RetransCount
		m.RetransRx = f.TCPPerfStats.TcpPerfCountsPeers[1].RetransCount
		m.ZeroWinTx = f.TCPPerfStats.TcpPerfCountsPeers[0].ZeroWinCount
		m.ZeroWinRx = f.TCPPerfStats.TcpPerfCountsPeers[1].ZeroWinCount
	}
}

func (f *FlowLogger) Release() {
	ReleaseFlowLogger(f)
}

func (f *FlowLogger) EndTime() time.Duration {
	return time.Duration(f.FlowInfo.EndTime) * time.Second
}

func (f *FlowLogger) String() string {
	return fmt.Sprintf("flow: %+v\n", *f)
}

var poolFlowLogger = pool.NewLockFreePool(func() interface{} {
	l := new(FlowLogger)
	l.CastTypes0 = make([]string, 0)
	l.CastTypes1 = make([]string, 0)
	l.PacketSizes0 = make([]string, 0)
	l.PacketSizes1 = make([]string, 0)
	l.TTLs0 = make([]string, 0)
	l.TTLs1 = make([]string, 0)
	l.TCPFlags0 = make([]uint16, 0)
	l.TCPFlags1 = make([]uint16, 0)
	return l
})

func AcquireFlowLogger() *FlowLogger {
	return poolFlowLogger.Get().(*FlowLogger)
}

func ReleaseFlowLogger(l *FlowLogger) {
	if l == nil {
		return
	}
	castType0 := l.CastTypes0
	castType1 := l.CastTypes1
	packetSizes0 := l.PacketSizes0
	packetSizes1 := l.PacketSizes1
	TTLs0 := l.TTLs0
	TTLs1 := l.TTLs1
	TCPFlags0 := l.TCPFlags0
	TCPFlags1 := l.TCPFlags1
	*l = FlowLogger{}
	l.CastTypes0 = castType0[:0]
	l.CastTypes1 = castType1[:0]
	l.PacketSizes0 = packetSizes0[:0]
	l.PacketSizes1 = packetSizes1[:0]
	l.TTLs0 = TTLs0[:0]
	l.TTLs1 = TTLs1[:0]
	l.TCPFlags0 = TCPFlags0[:0]
	l.TCPFlags1 = TCPFlags1[:0]
	poolFlowLogger.Put(l)
}

func TaggedFlowToLogger(f *datatype.TaggedFlow) *FlowLogger {
	isIPV6 := f.EthType == layers.EthernetTypeIPv6

	s := AcquireFlowLogger()
	s.DataLinkLayer.Fill(f)
	s.NetworkLayer.Fill(f, isIPV6)
	s.TransportLayer.Fill(f)
	s.ApplicationLayer.Fill(f)
	s.Internet.Fill(f)
	s.KnowledgeGraph.Fill(f, isIPV6)
	s.FlowInfo.Fill(f)
	s.Metrics.Fill(f)

	return s
}
