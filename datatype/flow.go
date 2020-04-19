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
	CloseTypeForcedReport
	// CloseTypeFoecedClose is not used any more, so skip it
	CloseTypeServerHalfOpen CloseType = iota + 1
	CloseTypeServerHalfClose
	CloseTypeTCPClientRst
	CloseTypeClientHalfOpen
	CloseTypeClientHalfClose
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

type FlowKey struct {
	TunnelInfo

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

func (_ *FlowKey) SequentialMerge(_ *FlowKey) {
	// 所有字段均无需改变
}

func (f *FlowKey) Encode(encoder *codec.SimpleEncoder) {
	f.TunnelInfo.Encode(encoder)

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
	f.TunnelInfo.Decode(decoder)

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

type TcpPerfCountsPeer struct {
	RetransCount uint32
	ZeroWinCount uint32
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

type TcpPerfStats struct { // 除特殊说明外，均为每个流统计周期（目前是自然分）清零
	RTTSum         uint32 // us
	RTTClientSum   uint32 // us
	RTTServerSum   uint32 // us
	SRTSum         uint32 // us
	ARTSum         uint32 // us
	RTTCount       uint32
	RTTClientCount uint32
	RTTServerCount uint32
	SRTCount       uint32
	ARTCount       uint32

	TcpPerfCountsPeers [2]TcpPerfCountsPeer
	TotalRetransCount  uint32 // 整个Flow生命周期的统计量
}

func (f *TcpPerfStats) SequentialMerge(rhs *TcpPerfStats) {
	f.RTTSum += rhs.RTTSum
	f.RTTClientSum += rhs.RTTClientSum
	f.RTTServerSum += rhs.RTTServerSum
	f.SRTSum += rhs.SRTSum
	f.ARTSum += rhs.ARTSum
	f.RTTCount += rhs.RTTCount
	f.RTTClientCount += rhs.RTTClientCount
	f.RTTServerCount += rhs.RTTServerCount
	f.SRTCount += rhs.SRTCount
	f.ARTCount += rhs.ARTCount
	f.TcpPerfCountsPeers[0].SequentialMerge(&rhs.TcpPerfCountsPeers[0])
	f.TcpPerfCountsPeers[1].SequentialMerge(&rhs.TcpPerfCountsPeers[1])
	f.TotalRetransCount = rhs.TotalRetransCount
}

func (f *TcpPerfStats) Reverse() {
	f.RTTClientSum, f.RTTServerSum = f.RTTServerSum, f.RTTClientSum
	f.RTTClientCount, f.RTTServerCount = f.RTTServerCount, f.RTTClientCount
	f.TcpPerfCountsPeers[0], f.TcpPerfCountsPeers[1] = f.TcpPerfCountsPeers[1], f.TcpPerfCountsPeers[0]
}

func (f *TcpPerfStats) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU32(f.RTTSum)
	encoder.WriteVarintU32(f.RTTClientSum)
	encoder.WriteVarintU32(f.RTTServerSum)
	encoder.WriteVarintU32(f.SRTSum)
	encoder.WriteVarintU32(f.ARTSum)
	encoder.WriteVarintU32(f.RTTCount)
	encoder.WriteVarintU32(f.RTTClientCount)
	encoder.WriteVarintU32(f.RTTServerCount)
	encoder.WriteVarintU32(f.SRTCount)
	encoder.WriteVarintU32(f.ARTCount)

	f.TcpPerfCountsPeers[0].Encode(encoder)
	f.TcpPerfCountsPeers[1].Encode(encoder)

	encoder.WriteVarintU32(f.TotalRetransCount)
}

func (f *TcpPerfStats) Decode(decoder *codec.SimpleDecoder) {
	f.RTTSum = decoder.ReadVarintU32()
	f.RTTClientSum = decoder.ReadVarintU32()
	f.RTTServerSum = decoder.ReadVarintU32()
	f.SRTSum = decoder.ReadVarintU32()
	f.ARTSum = decoder.ReadVarintU32()
	f.RTTCount = decoder.ReadVarintU32()
	f.RTTClientCount = decoder.ReadVarintU32()
	f.RTTServerCount = decoder.ReadVarintU32()
	f.SRTCount = decoder.ReadVarintU32()
	f.ARTCount = decoder.ReadVarintU32()

	f.TcpPerfCountsPeers[0].Decode(decoder)
	f.TcpPerfCountsPeers[1].Decode(decoder)

	f.TotalRetransCount = decoder.ReadVarintU32()
}

type FlowMetricsPeer struct {
	// 注意字节对齐!
	ByteCount        uint64        // 每个流统计周期（目前是自然秒）清零
	PacketCount      uint64        // 每个流统计周期（目前是自然秒）清零
	TotalByteCount   uint64        // 整个Flow生命周期的统计量
	TotalPacketCount uint64        // 整个Flow生命周期的统计量
	First, Last      time.Duration // 整个Flow生命周期首包和尾包的时间戳
	TCPFlags         uint8
	L3EpcID          int32
	IsL2End          bool
	IsL3End          bool
	IsActiveHost     bool
	IsDevice         bool // true表明是从平台数据中获取的
}

func (f *FlowMetricsPeer) SequentialMerge(rhs *FlowMetricsPeer) {
	f.ByteCount += rhs.ByteCount
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
}

func (f *FlowMetricsPeer) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(f.ByteCount)
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
}

func (f *FlowMetricsPeer) Decode(decoder *codec.SimpleDecoder) {
	f.ByteCount = decoder.ReadVarintU64()
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
}

const (
	FLOW_METRICS_PEER_SRC = iota
	FLOW_METRICS_PEER_DST
	FLOW_METRICS_PEER_MAX
)

// 结构或顺序变化，需要同步修改Encode和Decode
type Flow struct {
	// 注意字节对齐!
	FlowKey
	FlowMetricsPeers [FLOW_METRICS_PEER_MAX]FlowMetricsPeer

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
	*TcpPerfStats

	CloseType
	FlowSource
	IsActiveService bool
	QueueHash       uint8
	IsNewFlow       bool
	Reversed        bool
}

// FIXME 注意：由于FlowGenerator中TcpPerfStats在Flow方向调整之后才获取到，
// 因此这里不包含对TcpPerfStats的反向。
func (f *Flow) Reverse() {
	f.Reversed = !f.Reversed
	f.TunnelInfo.Src, f.TunnelInfo.Dst = f.TunnelInfo.Dst, f.TunnelInfo.Src
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

	if rhs.TcpPerfStats != nil {
		if f.TcpPerfStats == nil {
			f.TcpPerfStats = AcquireTcpPerfStats()
		}
		f.TcpPerfStats.SequentialMerge(rhs.TcpPerfStats)
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

	encoder.WriteU64(f.FlowID)
	encoder.WriteU32(f.Exporter)

	encoder.WriteU64(uint64(f.StartTime))
	encoder.WriteU64(uint64(f.EndTime))
	encoder.WriteU64(uint64(f.Duration))
	// encoder.WriteU64(uint64(f.FlowStatTime)) // 目前无需发送，不用encode(下面注释掉的，同理)

	// encoder.WriteU16(f.VLAN)
	encoder.WriteU16(uint16(f.EthType))

	if f.TcpPerfStats != nil {
		encoder.WriteBool(true)
		f.TcpPerfStats.Encode(encoder)
	} else {
		encoder.WriteBool(false)
	}

	encoder.WriteU8(uint8(f.CloseType))
	encoder.WriteU8(uint8(f.FlowSource))
	encoder.WriteBool(f.IsActiveService)
	// encoder.WriteU8(f.QueueHash)
	// encoder.WriteBool(f.IsNewFlow)
	// encoder.WriteBool(f.Reversed)
}

func (f *Flow) Decode(decoder *codec.SimpleDecoder) {
	f.FlowKey.Decode(decoder)
	for i := 0; i < FLOW_METRICS_PEER_MAX; i++ {
		f.FlowMetricsPeers[i].Decode(decoder)
	}

	f.FlowID = decoder.ReadU64()
	f.Exporter = decoder.ReadU32()

	f.StartTime = time.Duration(decoder.ReadU64())
	f.EndTime = time.Duration(decoder.ReadU64())
	f.Duration = time.Duration(decoder.ReadU64())
	// f.FlowStatTime = time.Duration(decoder.ReadU64())

	// f.VLAN = decoder.ReadU16()
	f.EthType = layers.EthernetType(decoder.ReadU16())

	if decoder.ReadBool() {
		f.TcpPerfStats = AcquireTcpPerfStats()
		f.TcpPerfStats.Decode(decoder)
	} else {
		f.TcpPerfStats = nil
	}

	f.CloseType = CloseType(decoder.ReadU8())
	f.FlowSource = FlowSource(decoder.ReadU8())
	f.IsActiveService = decoder.ReadBool()
	// f.QueueHash = decoder.ReadU8()
	// f.IsNewFlow = decoder.ReadBool()
	// f.Reversed = decoder.ReadBool()
}

func (t *TcpPerfStats) String() string {
	formatted := ""

	if t == nil {
		return ""
	}

	typeOf := reflect.TypeOf(*t)
	valueOf := reflect.ValueOf(*t)
	for i := 0; i < typeOf.NumField(); i++ {
		if i > 0 {
			formatted += " "
		}
		formatted += fmt.Sprintf("%v: %v", typeOf.Field(i).Name, valueOf.Field(i))
	}
	return formatted
}

func (f *FlowKey) String() string {
	formatted := ""
	formatted += fmt.Sprintf("TunnelInfo: {%s} ", f.TunnelInfo.String())
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
	if f.TcpPerfStats != nil {
		formatted += fmt.Sprintf("\n\t%s", f.TcpPerfStats.String())
	}
	return formatted
}

var tcpPerfStatsPool = pool.NewLockFreePool(func() interface{} {
	return new(TcpPerfStats)
})

func AcquireTcpPerfStats() *TcpPerfStats {
	return tcpPerfStatsPool.Get().(*TcpPerfStats)
}

func ReleaseTcpPerfStats(s *TcpPerfStats) {
	*s = TcpPerfStats{}
	tcpPerfStatsPool.Put(s)
}

func CloneTcpPerfStats(s *TcpPerfStats) *TcpPerfStats {
	newTcpPerfStats := AcquireTcpPerfStats()
	*newTcpPerfStats = *s
	return newTcpPerfStats
}
