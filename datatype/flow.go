package datatype

import (
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/google/gopacket/layers"

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

type FlowKey struct {
	TunnelInfo

	VtapId uint16
	InPort uint32
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

type TcpPerfCountsPeer struct {
	RetransCount uint32
	ZeroWinCount uint32
}

type TcpPerfCountsPeerSrc TcpPerfCountsPeer
type TcpPerfCountsPeerDst TcpPerfCountsPeer

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
	TcpPerfCountsPeerSrc
	TcpPerfCountsPeerDst
	TotalRetransCount uint32 // 整个Flow生命周期的统计量
}

type FlowMetricsPeer struct {
	// 注意字节对齐!
	TickByteCount    uint64        // 每个包统计周期（目前是自然秒）清零
	TickPacketCount  uint64        // 每个包统计周期（目前是自然秒）清零
	ByteCount        uint64        // 每个流统计周期（目前是自然分）清零
	PacketCount      uint64        // 每个流统计周期（目前是自然分）清零
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

const (
	FLOW_METRICS_PEER_SRC = iota
	FLOW_METRICS_PEER_DST
	FLOW_METRICS_PEER_MAX
)

type Flow struct {
	// 注意字节对齐!
	FlowKey
	FlowMetricsPeers [FLOW_METRICS_PEER_MAX]FlowMetricsPeer

	FlowID   uint64
	Exporter uint32

	/* Timers */
	StartTime      time.Duration
	EndTime        time.Duration
	Duration       time.Duration
	PacketStatTime time.Duration // 取整至包统计周期的开始
	FlowStatTime   time.Duration // 取整至流统计周期的开始

	/* L2 */
	VLAN    uint16
	EthType layers.EthernetType

	/* TCP Perf Data */
	*TcpPerfStats

	CloseType
	IsActiveService bool
	QueueHash       uint8
	IsNewFlow       bool
}

func (t *TcpPerfStats) String() string {
	formatted := ""

	if t == nil {
		return ""
	}

	typeOf := reflect.TypeOf(*t)
	valueOf := reflect.ValueOf(*t)
	for i := 0; i < typeOf.NumField(); i++ {
		formatted += fmt.Sprintf("%v: %v ", typeOf.Field(i).Name, valueOf.Field(i))
	}
	return formatted
}

func (f *FlowKey) String() string {
	formatted := ""
	formatted += fmt.Sprintf("TunnelInfo: {%s} ", f.TunnelInfo.String())
	formatted += fmt.Sprintf("VtapId: %d ", f.VtapId)
	formatted += fmt.Sprintf("InPort: %d\n", f.InPort)
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
	formatted += fmt.Sprintf("Exporter: %s ", IpFromUint32(f.Exporter))
	formatted += fmt.Sprintf("CloseType: %d ", f.CloseType)
	formatted += fmt.Sprintf("IsActiveService: %v ", f.IsActiveService)
	formatted += fmt.Sprintf("QueueHash: %d ", f.QueueHash)
	formatted += fmt.Sprintf("PacketStatTime: %d ", f.PacketStatTime/time.Second)
	formatted += fmt.Sprintf("FlowStatTime: %d\n", f.FlowStatTime/time.Second)
	formatted += fmt.Sprintf("\tStartTime: %d ", f.StartTime)
	formatted += fmt.Sprintf("EndTime: %d ", f.EndTime)
	formatted += fmt.Sprintf("Duration: %d\n", f.Duration)
	formatted += fmt.Sprintf("\tVLAN: %d ", f.VLAN)
	formatted += fmt.Sprintf("EthType: %d ", f.EthType)
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
