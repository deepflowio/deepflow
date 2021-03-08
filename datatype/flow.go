package datatype

import (
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

type CloseType uint8

const (
	CloseTypeUnknown CloseType = iota
	CloseTypeTCPFin
	CloseTypeTCPServerRst
	CloseTypeTimeout
	CloseTypeFlood
	CloseTypeForcedReport // 5
	_                     // CloseTypeFoecedClose is not used any more, so skip it
	CloseTypeClientSYNRepeat
	CloseTypeServerHalfClose
	CloseTypeTCPClientRst
	CloseTypeServerSYNACKRepeat // 10
	CloseTypeClientHalfClose

	_ // CloseTypeClientNoResponse is not used any more
	CloseTypeClientSourcePortReuse
	_                    // CloseTypeClientSYNRetryLack is not used any more
	CloseTypeServerReset // 15
	_                    // CloseTypeServerNoResponse is not used any more
	CloseTypeServerQueueLack
	CloseTypeClientEstablishReset
	CloseTypeServerEstablishReset
	MaxCloseType
)

type DeviceType uint8

const (
	unknownDeviceType DeviceType = iota
	VM
	VGw
	ThirdPartyDevice
	VMWAF
	NSPVGateway
	HostDevice
	NetworkDevice
	FloatingIP
)

type FlowSource uint8

const (
	FLOW_SOURCE_NORMAL FlowSource = iota
	FLOW_SOURCE_SFLOW
	FLOW_SOURCE_NETFLOW
)

type TcpPerfCountsPeer struct {
	RetransCount uint32
	ZeroWinCount uint32
}

// size = 20 * 4B = 80Byte
// UDPPerfStats仅有2个字段，复用ARTSum, ARTCount
type TCPPerfStats struct { // 除特殊说明外，均为每个流统计周期（目前是自然分）清零
	RTTClientMax uint32 // us，Trident保证时延最大值不会超过3600s，能容纳在u32内
	RTTServerMax uint32 // us
	SRTMax       uint32 // us
	ARTMax       uint32 // us，UDP复用

	RTT            uint32 // us，TCP建连过程，只会计算出一个RTT
	RTTClientSum   uint32 // us，假定一条流在一分钟内的时延加和不会超过u32
	RTTServerSum   uint32 // us
	SRTSum         uint32 // us
	ARTSum         uint32 // us，UDP复用
	RTTClientCount uint32
	RTTServerCount uint32
	SRTCount       uint32
	ARTCount       uint32 // UDP复用

	TcpPerfCountsPeers [2]TcpPerfCountsPeer
	TotalRetransCount  uint32 // 整个Flow生命周期的统计量
}

type L4Protocol uint8

const (
	L4_PROTOCOL_UNKOWN L4Protocol = iota
	L4_PROTOCOL_TCP
	L4_PROTOCOL_UDP

	L4_PROTOCOL_MAX
)

type L7Protocol uint8

const (
	L7_PROTOCOL_UNKOWN L7Protocol = iota
	L7_PROTOCOL_HTTP
	L7_PROTOCOL_DNS

	L7_PROTOCOL_MAX
)

// size = 9 * 4B = 36B
type L7PerfStats struct {
	RequestCount   uint32
	ResponseCount  uint32
	ErrClientCount uint32 // client端原因导致的响应异常数量
	ErrServerCount uint32 // server端原因导致的响应异常数量
	ErrTimeout     uint32 // request请求timeout数量
	RRTCount       uint32 // u32可记录40000M时延，一条流在一分钟内的请求数远无法达到此数值
	RRTSum         uint64 // us RRT(Request Response Time)
	RRTMax         uint32 // us RRT(Request Response Time)，Trident保证在3600s以内
}

// size = 80B + 36B + 2B = 118B
type FlowPerfStats struct {
	TCPPerfStats
	L7PerfStats
	L4Protocol
	L7Protocol
}

type FlowMetricsPeer struct {
	// 注意字节对齐!
	ByteCount        uint64        // 每个流统计周期（目前是自然秒）清零
	L3ByteCount      uint64        // 每个流统计周期的L3载荷量
	L4ByteCount      uint64        // 每个流统计周期的L4载荷量
	PacketCount      uint64        // 每个流统计周期（目前是自然秒）清零
	TotalByteCount   uint64        // 整个Flow生命周期的统计量
	TotalPacketCount uint64        // 整个Flow生命周期的统计量
	First, Last      time.Duration // 整个Flow生命周期首包和尾包的时间戳
	L3EpcID          int32
	IsL2End          bool
	IsL3End          bool
	IsActiveHost     bool
	IsDevice         bool  // true表明是从平台数据中获取的
	TCPFlags         uint8 // 所有TCP的Flags或运算
	IsVIPInterface   bool  // 目前仅支持微软Mux设备，从grpc Interface中获取
	IsVIP            bool  // 从grpc cidr中获取

	CastTypeMap   uint8  // 仅包含TSDB中的几个CastType标志位选项
	TCPFlagsMap   uint16 // 仅包含TSDB中的几个TCP标志位选项
	TTLMap        uint16 // 仅包含TSDB中的几个TTL标志位选项
	PacketSizeMap uint16 // 仅包含TSDB中的几个PacketSize标志位选项
}

const (
	FLOW_METRICS_PEER_SRC = iota
	FLOW_METRICS_PEER_DST
	FLOW_METRICS_PEER_MAX
)

type FlowKey struct {
	VtapId  uint16
	TapType TapType
	TapPort uint32
	/* L2 */
	MACSrc MacInt
	MACDst MacInt
	/* L3 */
	IPSrc IPv4Int
	IPDst IPv4Int
	/* L3 IPv6 */
	IP6Src net.IP
	IP6Dst net.IP
	/* L4 */
	PortSrc uint16
	PortDst uint16
	Proto   layers.IPProtocol
}

type TunnelField struct {
	TxIP0, TxIP1 IPv4Int // 对应发送方向的源目的隧道IP
	RxIP0, RxIP1 IPv4Int // 对应接收方向的源目的隧道IP
	TxId, RxId   uint32
	Type         TunnelType
	Tier         uint8
}

func (f *TunnelField) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU32(f.TxIP0)
	encoder.WriteU32(f.TxIP1)
	encoder.WriteU32(f.RxIP0)
	encoder.WriteU32(f.RxIP1)
	encoder.WriteU32(f.TxId)
	encoder.WriteU32(f.RxId)
	encoder.WriteU8(uint8(f.Type))
	encoder.WriteU8(f.Tier)
}

func (f *TunnelField) Decode(decoder *codec.SimpleDecoder) {
	f.TxIP0 = decoder.ReadU32()
	f.TxIP1 = decoder.ReadU32()
	f.RxIP0 = decoder.ReadU32()
	f.RxIP1 = decoder.ReadU32()
	f.TxId = decoder.ReadU32()
	f.RxId = decoder.ReadU32()
	f.Type = TunnelType(decoder.ReadU8())
	f.Tier = decoder.ReadU8()
}

func (t *TunnelField) String() string {
	if t.Type == TUNNEL_TYPE_NONE {
		return "none "
	}
	return fmt.Sprintf("type: %s, tx_id: %d, rx_id: %d, tier: %d, tx_ip_0: %s, tx_ip_1: %s, rx_ip_0: %s, rx_ip_1: %s ",
		t.Type, t.TxId, t.RxId, t.Tier,
		IpFromUint32(t.TxIP0), IpFromUint32(t.TxIP1),
		IpFromUint32(t.RxIP0), IpFromUint32(t.RxIP1))
}

// 结构或顺序变化，需要同步修改Encode和Decode
type Flow struct {
	// 注意字节对齐!
	FlowKey
	FlowMetricsPeers [FLOW_METRICS_PEER_MAX]FlowMetricsPeer

	Tunnel TunnelField

	FlowID   uint64
	Exporter uint32

	/* Timers */
	StartTime    time.Duration
	EndTime      time.Duration
	Duration     time.Duration
	FlowStatTime time.Duration // 取整至流统计周期的开始

	/* L2 */
	VLAN    uint16
	EthType layers.EthernetType

	/* TCP Perf Data */
	*FlowPerfStats

	CloseType
	FlowSource
	IsActiveService bool
	QueueHash       uint8
	IsNewFlow       bool
	Reversed        bool
}

func (t FlowSource) String() string {
	switch t {
	case FLOW_SOURCE_NORMAL:
		return "normal"
	case FLOW_SOURCE_SFLOW:
		return "sflow"
	case FLOW_SOURCE_NETFLOW:
		return "netflow"
	default:
		return "unkown flow source"
	}
}

func (_ *FlowKey) SequentialMerge(_ *FlowKey) {
	// 所有字段均无需改变
}

func (f *FlowKey) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU16(f.VtapId)
	encoder.WriteU16(uint16(f.TapType))
	encoder.WriteU32(f.TapPort)

	encoder.WriteU64(f.MACSrc)
	encoder.WriteU64(f.MACDst)

	if len(f.IP6Src) > 0 {
		encoder.WriteBool(true) // 额外encode bool, decode时需要根据该bool, 来判断是否decode ipv6
		encoder.WriteIPv6(f.IP6Src)
		encoder.WriteIPv6(f.IP6Dst)
	} else {
		encoder.WriteBool(false)
		encoder.WriteU32(f.IPSrc)
		encoder.WriteU32(f.IPDst)
	}

	encoder.WriteU16(f.PortSrc)
	encoder.WriteU16(f.PortDst)
	encoder.WriteU8(uint8(f.Proto))
}

func (f *FlowKey) Decode(decoder *codec.SimpleDecoder) {
	f.VtapId = decoder.ReadU16()
	f.TapType = TapType(decoder.ReadU16())
	f.TapPort = decoder.ReadU32()

	f.MACSrc = decoder.ReadU64()
	f.MACDst = decoder.ReadU64()

	if decoder.ReadBool() {
		if f.IP6Src == nil {
			f.IP6Src = make([]byte, 16)
		}
		decoder.ReadIPv6(f.IP6Src)
		if f.IP6Dst == nil {
			f.IP6Dst = make([]byte, 16)
		}
		decoder.ReadIPv6(f.IP6Dst)
	} else {
		f.IPSrc = decoder.ReadU32()
		f.IPDst = decoder.ReadU32()
		f.IP6Src = nil
		f.IP6Dst = nil
	}

	f.PortSrc = decoder.ReadU16()
	f.PortDst = decoder.ReadU16()
	f.Proto = layers.IPProtocol(decoder.ReadU8())
}

func (f *TcpPerfCountsPeer) SequentialMerge(rhs *TcpPerfCountsPeer) {
	f.RetransCount += rhs.RetransCount
	f.ZeroWinCount += rhs.ZeroWinCount
}

func (t *TcpPerfCountsPeer) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU32(t.RetransCount)
	encoder.WriteVarintU32(t.ZeroWinCount)
}

func (t *TcpPerfCountsPeer) Decode(decoder *codec.SimpleDecoder) {
	t.RetransCount = decoder.ReadVarintU32()
	t.ZeroWinCount = decoder.ReadVarintU32()
}

func (f *TCPPerfStats) SequentialMerge(rhs *TCPPerfStats) {
	if f.RTTClientMax < rhs.RTTClientMax {
		f.RTTClientMax = rhs.RTTClientMax
	}
	if f.RTTServerMax < rhs.RTTServerMax {
		f.RTTServerMax = rhs.RTTServerMax
	}
	if f.SRTMax < rhs.SRTMax {
		f.SRTMax = rhs.SRTMax
	}
	if f.ARTMax < rhs.ARTMax {
		f.ARTMax = rhs.ARTMax
	}

	if f.RTT < rhs.RTT {
		f.RTT = rhs.RTT
	}
	f.RTTClientSum += rhs.RTTClientSum
	f.RTTServerSum += rhs.RTTServerSum
	f.SRTSum += rhs.SRTSum
	f.ARTSum += rhs.ARTSum
	f.RTTClientCount += rhs.RTTClientCount
	f.RTTServerCount += rhs.RTTServerCount
	f.SRTCount += rhs.SRTCount
	f.ARTCount += rhs.ARTCount
	f.TcpPerfCountsPeers[0].SequentialMerge(&rhs.TcpPerfCountsPeers[0])
	f.TcpPerfCountsPeers[1].SequentialMerge(&rhs.TcpPerfCountsPeers[1])
	f.TotalRetransCount = rhs.TotalRetransCount
}

func (f *TCPPerfStats) Reverse() {
	f.RTTClientSum, f.RTTServerSum = f.RTTServerSum, f.RTTClientSum
	f.RTTClientCount, f.RTTServerCount = f.RTTServerCount, f.RTTClientCount
	f.TcpPerfCountsPeers[0], f.TcpPerfCountsPeers[1] = f.TcpPerfCountsPeers[1], f.TcpPerfCountsPeers[0]
}

func (f *TCPPerfStats) Encode(encoder *codec.SimpleEncoder, l4Protocol L4Protocol) {
	if l4Protocol == L4_PROTOCOL_TCP {
		encoder.WriteVarintU32(f.RTTClientMax)
		encoder.WriteVarintU32(f.RTTServerMax)
		encoder.WriteVarintU32(f.SRTMax)
		encoder.WriteVarintU32(f.ARTMax)

		encoder.WriteVarintU32(f.RTT)
		encoder.WriteVarintU32(f.RTTClientSum)
		encoder.WriteVarintU32(f.RTTServerSum)
		encoder.WriteVarintU32(f.SRTSum)
		encoder.WriteVarintU32(f.ARTSum)
		encoder.WriteVarintU32(f.RTTClientCount)
		encoder.WriteVarintU32(f.RTTServerCount)
		encoder.WriteVarintU32(f.SRTCount)
		encoder.WriteVarintU32(f.ARTCount)

		f.TcpPerfCountsPeers[0].Encode(encoder)
		f.TcpPerfCountsPeers[1].Encode(encoder)

		encoder.WriteVarintU32(f.TotalRetransCount)
	} else if l4Protocol == L4_PROTOCOL_UDP {
		encoder.WriteVarintU32(f.ARTMax)
		encoder.WriteVarintU32(f.ARTSum)
		encoder.WriteVarintU32(f.ARTCount)
	}
}

func (f *TCPPerfStats) Decode(decoder *codec.SimpleDecoder, l4Protocol L4Protocol) {
	if l4Protocol == L4_PROTOCOL_TCP {
		f.RTTClientMax = decoder.ReadVarintU32()
		f.RTTServerMax = decoder.ReadVarintU32()
		f.SRTMax = decoder.ReadVarintU32()
		f.ARTMax = decoder.ReadVarintU32()

		f.RTT = decoder.ReadVarintU32()
		f.RTTClientSum = decoder.ReadVarintU32()
		f.RTTServerSum = decoder.ReadVarintU32()
		f.SRTSum = decoder.ReadVarintU32()
		f.ARTSum = decoder.ReadVarintU32()
		f.RTTClientCount = decoder.ReadVarintU32()
		f.RTTServerCount = decoder.ReadVarintU32()
		f.SRTCount = decoder.ReadVarintU32()
		f.ARTCount = decoder.ReadVarintU32()

		f.TcpPerfCountsPeers[0].Decode(decoder)
		f.TcpPerfCountsPeers[1].Decode(decoder)

		f.TotalRetransCount = decoder.ReadVarintU32()
	} else if l4Protocol == L4_PROTOCOL_UDP {
		f.ARTMax = decoder.ReadVarintU32()
		f.ARTSum = decoder.ReadVarintU32()
		f.ARTCount = decoder.ReadVarintU32()
	}
}

func (f *FlowMetricsPeer) SequentialMerge(rhs *FlowMetricsPeer) {
	f.ByteCount += rhs.ByteCount
	f.L3ByteCount += rhs.L3ByteCount
	f.L4ByteCount += rhs.L4ByteCount
	f.PacketCount += rhs.PacketCount
	f.TotalByteCount = rhs.TotalByteCount
	f.TotalPacketCount = rhs.TotalPacketCount
	f.First = rhs.First
	f.Last = rhs.Last
	f.TCPFlags |= rhs.TCPFlags
	f.L3EpcID = rhs.L3EpcID
	f.IsL2End = rhs.IsL2End
	f.IsL3End = rhs.IsL3End
	f.IsActiveHost = rhs.IsActiveHost
	f.IsDevice = rhs.IsDevice
	f.CastTypeMap |= rhs.CastTypeMap
	f.TCPFlagsMap |= rhs.TCPFlagsMap
	f.TTLMap |= rhs.TTLMap
	f.PacketSizeMap |= rhs.PacketSizeMap
}

func (f *FlowMetricsPeer) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(f.ByteCount)
	encoder.WriteVarintU64(f.L3ByteCount)
	encoder.WriteVarintU64(f.L4ByteCount)
	encoder.WriteVarintU64(f.PacketCount)
	encoder.WriteVarintU64(f.TotalByteCount)
	encoder.WriteVarintU64(f.TotalPacketCount)

	encoder.WriteU64(uint64(f.First))
	encoder.WriteU64(uint64(f.Last))
	encoder.WriteU8(f.TCPFlags)
	encoder.WriteU32(uint32(f.L3EpcID))

	encoder.WriteBool(f.IsL2End)
	encoder.WriteBool(f.IsL3End)
	encoder.WriteBool(f.IsActiveHost)
	encoder.WriteBool(f.IsDevice)
	encoder.WriteBool(f.IsVIPInterface)
	encoder.WriteBool(f.IsVIP)

	encoder.WriteU8(f.CastTypeMap)
	encoder.WriteU16(f.TCPFlagsMap)
	encoder.WriteU16(f.TTLMap)
	encoder.WriteU16(f.PacketSizeMap)
}

func (f *FlowMetricsPeer) Decode(decoder *codec.SimpleDecoder) {
	f.ByteCount = decoder.ReadVarintU64()
	f.L3ByteCount = decoder.ReadVarintU64()
	f.L4ByteCount = decoder.ReadVarintU64()
	f.PacketCount = decoder.ReadVarintU64()
	f.TotalByteCount = decoder.ReadVarintU64()
	f.TotalPacketCount = decoder.ReadVarintU64()

	f.First = time.Duration(decoder.ReadU64())
	f.Last = time.Duration(decoder.ReadU64())
	f.TCPFlags = decoder.ReadU8()
	f.L3EpcID = int32(decoder.ReadU32())

	f.IsL2End = decoder.ReadBool()
	f.IsL3End = decoder.ReadBool()
	f.IsActiveHost = decoder.ReadBool()
	f.IsDevice = decoder.ReadBool()
	f.IsVIPInterface = decoder.ReadBool()
	f.IsVIP = decoder.ReadBool()

	f.CastTypeMap = decoder.ReadU8()
	f.TCPFlagsMap = decoder.ReadU16()
	f.TTLMap = decoder.ReadU16()
	f.PacketSizeMap = decoder.ReadU16()
}

// FIXME 注意：由于FlowGenerator中TCPPerfStats在Flow方向调整之后才获取到，
// 因此这里不包含对TCPPerfStats的反向。
func (f *Flow) Reverse() {
	f.Reversed = !f.Reversed
	f.Tunnel.TxIP0, f.Tunnel.TxIP1, f.Tunnel.RxIP0, f.Tunnel.RxIP1 = f.Tunnel.RxIP0, f.Tunnel.RxIP1, f.Tunnel.TxIP0, f.Tunnel.TxIP1
	f.Tunnel.TxId, f.Tunnel.RxId = f.Tunnel.RxId, f.Tunnel.TxId
	f.MACSrc, f.MACDst = f.MACDst, f.MACSrc
	f.IPSrc, f.IPDst = f.IPDst, f.IPSrc
	f.IP6Src, f.IP6Dst = f.IP6Dst, f.IP6Src
	f.PortSrc, f.PortDst = f.PortDst, f.PortSrc
	flowMetricsPeerSrc := &f.FlowMetricsPeers[FLOW_METRICS_PEER_SRC]
	flowMetricsPeerDst := &f.FlowMetricsPeers[FLOW_METRICS_PEER_DST]
	*flowMetricsPeerSrc, *flowMetricsPeerDst = *flowMetricsPeerDst, *flowMetricsPeerSrc
}

func (f *Flow) SequentialMerge(rhs *Flow) {
	f.FlowKey.SequentialMerge(&rhs.FlowKey)
	f.FlowMetricsPeers[FLOW_METRICS_PEER_SRC].SequentialMerge(&rhs.FlowMetricsPeers[FLOW_METRICS_PEER_SRC])
	f.FlowMetricsPeers[FLOW_METRICS_PEER_DST].SequentialMerge(&rhs.FlowMetricsPeers[FLOW_METRICS_PEER_DST])

	f.EndTime = rhs.EndTime
	f.Duration = rhs.Duration

	if rhs.FlowPerfStats != nil {
		if f.FlowPerfStats == nil {
			f.FlowPerfStats = AcquireFlowPerfStats()
		}
		f.FlowPerfStats.SequentialMerge(rhs.FlowPerfStats)
	}

	f.CloseType = rhs.CloseType
	f.IsActiveService = rhs.IsActiveService
	f.Reversed = rhs.Reversed
}

func (f *Flow) Encode(encoder *codec.SimpleEncoder) {
	f.FlowKey.Encode(encoder)
	for i := 0; i < FLOW_METRICS_PEER_MAX; i++ {
		f.FlowMetricsPeers[i].Encode(encoder)
	}
	f.Tunnel.Encode(encoder)

	encoder.WriteU64(f.FlowID)
	encoder.WriteU32(f.Exporter)

	encoder.WriteU64(uint64(f.StartTime))
	encoder.WriteU64(uint64(f.EndTime))
	encoder.WriteU64(uint64(f.Duration))
	// encoder.WriteU64(uint64(f.FlowStatTime)) // 目前无需发送，不用encode(下面注释掉的，同理)

	// encoder.WriteU16(f.VLAN)
	encoder.WriteU16(uint16(f.EthType))

	if f.FlowPerfStats != nil {
		encoder.WriteBool(true)
		f.FlowPerfStats.Encode(encoder)
	} else {
		encoder.WriteBool(false)
	}

	encoder.WriteU8(uint8(f.CloseType))
	encoder.WriteU8(uint8(f.FlowSource))
	encoder.WriteBool(f.IsActiveService)
}

func (f *Flow) Decode(decoder *codec.SimpleDecoder) {
	f.FlowKey.Decode(decoder)
	for i := 0; i < FLOW_METRICS_PEER_MAX; i++ {
		f.FlowMetricsPeers[i].Decode(decoder)
	}
	f.Tunnel.Decode(decoder)

	f.FlowID = decoder.ReadU64()
	f.Exporter = decoder.ReadU32()

	f.StartTime = time.Duration(decoder.ReadU64())
	f.EndTime = time.Duration(decoder.ReadU64())
	f.Duration = time.Duration(decoder.ReadU64())
	// f.FlowStatTime = time.Duration(decoder.ReadU64())

	// f.VLAN = decoder.ReadU16()
	f.EthType = layers.EthernetType(decoder.ReadU16())

	if decoder.ReadBool() {
		f.FlowPerfStats = AcquireFlowPerfStats()
		f.FlowPerfStats.Decode(decoder)
	} else {
		f.FlowPerfStats = nil
	}

	f.CloseType = CloseType(decoder.ReadU8())
	f.FlowSource = FlowSource(decoder.ReadU8())
	f.IsActiveService = decoder.ReadBool()
}

func formatStruct(s interface{}) string {
	formatted := ""
	t := reflect.TypeOf(s)
	formatted += fmt.Sprintf("formatted kind:%v,%v;", t.Kind(), t.NumField())
	if t.Kind() != reflect.Struct {
		return ""
	}

	v := reflect.ValueOf(s)
	for i := 0; i < t.NumField(); i++ {
		if i > 0 {
			formatted += " "
		}
		formatted += fmt.Sprintf("%v: %v", t.Field(i).Name, v.Field(i))
	}
	return formatted
}

func (p *L7Protocol) String() string {
	formatted := ""
	switch *p {
	case L7_PROTOCOL_HTTP:
		formatted = "http"
	case L7_PROTOCOL_DNS:
		formatted = "dns"
	}
	return formatted
}

func (p *L4Protocol) String() string {
	formatted := ""
	switch *p {
	case L4_PROTOCOL_TCP:
		formatted = "tcp"
	case L4_PROTOCOL_UDP:
		formatted = "udp"
	}
	return formatted
}

func (p *L7PerfStats) String() string {
	formatted := ""
	formatted += fmt.Sprintf("RequestCount:%v ", p.RequestCount)
	formatted += fmt.Sprintf("ResponseCount:%v ", p.ResponseCount)
	formatted += fmt.Sprintf("ErrClientCount:%v ", p.ErrClientCount)
	formatted += fmt.Sprintf("ErrServerCount:%v ", p.ErrServerCount)
	formatted += fmt.Sprintf("ErrTimeout:%v ", p.ErrTimeout)
	formatted += fmt.Sprintf("RTTCount:%v ", p.RRTCount)
	formatted += fmt.Sprintf("RTTSum:%v ", p.RRTSum)
	formatted += fmt.Sprintf("RTTMax:%v", p.RRTMax)
	return formatted
}

func (p *TCPPerfStats) String() string {
	formatted := ""
	formatted += fmt.Sprintf("RTTClientMax:%v ", p.RTTClientMax)
	formatted += fmt.Sprintf("RTTServerMax:%v ", p.RTTServerMax)
	formatted += fmt.Sprintf("SRTMax:%v ", p.SRTMax)
	formatted += fmt.Sprintf("ARTMax:%v ", p.ARTMax)
	formatted += fmt.Sprintf("RTT:%v ", p.RTT)
	formatted += fmt.Sprintf("RTTClientSum:%v ", p.RTTClientSum)
	formatted += fmt.Sprintf("RTTServerSum:%v ", p.RTTServerSum)
	formatted += fmt.Sprintf("SRTSum:%v ", p.SRTSum)
	formatted += fmt.Sprintf("ARTSum:%v ", p.ARTSum)
	formatted += fmt.Sprintf("RTTClientCount:%v ", p.RTTClientCount)
	formatted += fmt.Sprintf("RTTServerCount:%v ", p.RTTServerCount)
	formatted += fmt.Sprintf("SRTCount:%v ", p.SRTCount)
	formatted += fmt.Sprintf("ARTCount:%v ", p.ARTCount)
	formatted += fmt.Sprintf("RetransCountSrc:%v ", p.TcpPerfCountsPeers[0].RetransCount)
	formatted += fmt.Sprintf("ZeroWinCountSrc:%v ", p.TcpPerfCountsPeers[0].ZeroWinCount)
	formatted += fmt.Sprintf("RetransCountDst:%v ", p.TcpPerfCountsPeers[1].RetransCount)
	formatted += fmt.Sprintf("ZeroWinCountDst:%v ", p.TcpPerfCountsPeers[1].ZeroWinCount)
	formatted += fmt.Sprintf("TotalRetransCount:%v", p.TotalRetransCount)

	return formatted
}

func (p *FlowPerfStats) String() string {
	if p == nil {
		return ""
	}

	formatted := ""
	formatted += fmt.Sprintf("L4Protocol:%s ", p.L4Protocol.String())
	formatted += fmt.Sprintf("TCPPerfStats:{%s} ", p.TCPPerfStats.String())
	formatted += fmt.Sprintf("\n\tL7Protocol:%s ", p.L7Protocol.String())
	formatted += fmt.Sprintf("L7PerfStats:{%s}", p.L7PerfStats.String())
	return formatted
}

func (f *FlowKey) String() string {
	formatted := ""
	formatted += fmt.Sprintf("VtapId: %d ", f.VtapId)
	formatted += fmt.Sprintf("TapType: %d ", f.TapType)
	formatted += fmt.Sprintf("TapPort: 0x%x\n", f.TapPort)
	formatted += fmt.Sprintf("\tMACSrc: %s ", Uint64ToMac(f.MACSrc))
	formatted += fmt.Sprintf("MACDst: %s ", Uint64ToMac(f.MACDst))
	if len(f.IP6Src) > 0 {
		formatted += fmt.Sprintf("IP6Src: %s ", f.IP6Src)
		formatted += fmt.Sprintf("IP6Dst: %s ", f.IP6Dst)
	} else {
		formatted += fmt.Sprintf("IPSrc: %s ", IpFromUint32(f.IPSrc))
		formatted += fmt.Sprintf("IPDst: %s ", IpFromUint32(f.IPDst))
	}
	formatted += fmt.Sprintf("Proto: %v ", f.Proto)
	formatted += fmt.Sprintf("PortSrc: %d ", f.PortSrc)
	formatted += fmt.Sprintf("PortDst: %d", f.PortDst)
	return formatted
}

func (f *FlowMetricsPeer) String() string {
	formatted := ""
	typeOf := reflect.TypeOf(*f)
	valueOf := reflect.ValueOf(*f)
	for i := 0; i < typeOf.NumField(); i++ {
		field := typeOf.Field(i)
		value := valueOf.Field(i)
		if field.Type.Name() == "Duration" {
			formatted += fmt.Sprintf("%v: %d ", field.Name, value.Int())
		} else {
			formatted += fmt.Sprintf("%v: %+v ", field.Name, value)
		}
	}
	return formatted
}

func (f *Flow) String() string {
	formatted := fmt.Sprintf("FlowID: %d ", f.FlowID)
	formatted += fmt.Sprintf("FlowSource: %s ", f.FlowSource.String())
	formatted += fmt.Sprintf("Tunnel: %s ", f.Tunnel.String())
	formatted += fmt.Sprintf("Exporter: %s ", IpFromUint32(f.Exporter))
	formatted += fmt.Sprintf("CloseType: %d ", f.CloseType)
	formatted += fmt.Sprintf("IsActiveService: %v ", f.IsActiveService)
	formatted += fmt.Sprintf("IsNewFlow: %v ", f.IsNewFlow)
	formatted += fmt.Sprintf("QueueHash: %d ", f.QueueHash)
	formatted += fmt.Sprintf("FlowStatTime: %d\n", f.FlowStatTime/time.Second)
	formatted += fmt.Sprintf("\tStartTime: %d ", f.StartTime)
	formatted += fmt.Sprintf("EndTime: %d ", f.EndTime)
	formatted += fmt.Sprintf("Duration: %d\n", f.Duration)
	formatted += fmt.Sprintf("\tVLAN: %d ", f.VLAN)
	formatted += fmt.Sprintf("EthType: %d ", f.EthType)
	formatted += fmt.Sprintf("Reversed: %v ", f.Reversed)
	formatted += fmt.Sprintf("%s\n", f.FlowKey.String())
	formatted += fmt.Sprintf("\tFlowMetricsPeerSrc: {%s}\n", f.FlowMetricsPeers[FLOW_METRICS_PEER_SRC].String())
	formatted += fmt.Sprintf("\tFlowMetricsPeerDst: {%s}", f.FlowMetricsPeers[FLOW_METRICS_PEER_DST].String())
	if f.FlowPerfStats != nil {
		formatted += fmt.Sprintf("\n\t%s", f.FlowPerfStats.String())
	}
	return formatted
}

var zeroFlowPerfStats FlowPerfStats = FlowPerfStats{}
var flowPerfStatsPool = pool.NewLockFreePool(func() interface{} {
	return new(FlowPerfStats)
})

func AcquireFlowPerfStats() *FlowPerfStats {
	return flowPerfStatsPool.Get().(*FlowPerfStats)
}

func ReleaseFlowPerfStats(s *FlowPerfStats) {
	*s = zeroFlowPerfStats
	flowPerfStatsPool.Put(s)
}

func CloneFlowPerfStats(s *FlowPerfStats) *FlowPerfStats {
	newFlowPerfStats := AcquireFlowPerfStats()
	*newFlowPerfStats = *s
	return newFlowPerfStats
}

func (p *L7PerfStats) Decode(decoder *codec.SimpleDecoder) {
	p.RequestCount = decoder.ReadVarintU32()
	p.ResponseCount = decoder.ReadVarintU32()
	p.ErrClientCount = decoder.ReadVarintU32()
	p.ErrServerCount = decoder.ReadVarintU32()
	p.ErrTimeout = decoder.ReadVarintU32()
	p.RRTCount = decoder.ReadVarintU32()
	p.RRTSum = decoder.ReadVarintU64()
	p.RRTMax = decoder.ReadVarintU32()
}

func (p *L7PerfStats) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU32(p.RequestCount)
	encoder.WriteVarintU32(p.ResponseCount)
	encoder.WriteVarintU32(p.ErrClientCount)
	encoder.WriteVarintU32(p.ErrServerCount)
	encoder.WriteVarintU32(p.ErrTimeout)
	encoder.WriteVarintU32(p.RRTCount)
	encoder.WriteVarintU64(p.RRTSum)
	encoder.WriteVarintU32(p.RRTMax)
}

func (p *L7PerfStats) SequentialMerge(rhs *L7PerfStats) {
	p.RequestCount += rhs.RequestCount
	p.ResponseCount += rhs.ResponseCount
	p.ErrClientCount += rhs.ErrClientCount
	p.ErrServerCount += rhs.ErrServerCount
	p.ErrTimeout += rhs.ErrTimeout
	p.RRTCount += rhs.RRTCount
	p.RRTSum += rhs.RRTSum
	if p.RRTMax < rhs.RRTMax {
		p.RRTMax = rhs.RRTMax
	}
}

func (f *FlowPerfStats) Decode(decoder *codec.SimpleDecoder) {
	f.L4Protocol = L4Protocol(decoder.ReadU8())
	f.L7Protocol = L7Protocol(decoder.ReadU8())

	f.TCPPerfStats.Decode(decoder, f.L4Protocol)
	f.L7PerfStats.Decode(decoder)
}

func (f *FlowPerfStats) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU8(uint8(f.L4Protocol))
	encoder.WriteU8(uint8(f.L7Protocol))

	f.TCPPerfStats.Encode(encoder, f.L4Protocol)
	f.L7PerfStats.Encode(encoder)
}

func (f *FlowPerfStats) SequentialMerge(rhs *FlowPerfStats) {
	f.TCPPerfStats.SequentialMerge(&rhs.TCPPerfStats)
	f.L7PerfStats.SequentialMerge(&rhs.L7PerfStats)
}
