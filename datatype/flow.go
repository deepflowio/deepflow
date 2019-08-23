package datatype

import (
	"fmt"
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

	Exporter IPv4Int
	InPort   uint32
	/* L2 */
	MACSrc MacInt
	MACDst MacInt
	/* L3 */
	IPSrc IPv4Int
	IPDst IPv4Int
	/* L4 */
	PortSrc uint16
	PortDst uint16
	Proto   layers.IPProtocol
}

type TcpPerfCountsPeer struct {
	SynRetransCount uint32
	RetransCount    uint32
	ZeroWinCount    uint32
	PshUrgCount     uint32
}

type TcpPerfCountsPeerSrc TcpPerfCountsPeer
type TcpPerfCountsPeerDst TcpPerfCountsPeer

type TcpPerfStats struct {
	RTTSyn       time.Duration
	RTTSynClient time.Duration
	RTTSynServer time.Duration
	RTT          time.Duration
	ART          time.Duration
	TcpPerfCountsPeerSrc
	TcpPerfCountsPeerDst
	PacketIntervalAvg      uint64
	PacketIntervalVariance uint64
	PacketSizeVariance     uint64
	TotalRetransCount      uint32
	TotalZeroWinCount      uint32
	TotalPshUrgCount       uint32
}

type FlowMetricsPeer struct {
	// 注意字节对齐!
	ByteCount        uint64
	PacketCount      uint64
	TotalByteCount   uint64
	TotalPacketCount uint64
	ArrTime0         time.Duration
	ArrTimeLast      time.Duration
	SubnetID         uint32
	L3DeviceID       uint32
	DeviceID         uint32
	L3EpcID          int32
	EpcID            int32
	Host             uint32
	IfIndex          uint32
	IfType           uint32
	L3DeviceType     DeviceType
	DeviceType       DeviceType
	TCPFlags         uint8
	IsL2End          bool
	IsL3End          bool
}

type FlowMetricsPeerSrc FlowMetricsPeer

type FlowMetricsPeerDst FlowMetricsPeer

type Flow struct {
	// 注意字节对齐!
	FlowKey
	FlowMetricsPeerSrc
	FlowMetricsPeerDst

	FlowID     uint64
	TimeBitmap uint64
	QueueHash  uint8

	/* Timers */
	StartTime    time.Duration
	CurStartTime time.Duration
	EndTime      time.Duration
	Duration     time.Duration

	/* L2 */
	VLAN    uint16
	EthType layers.EthernetType

	/* TCP Perf Data */
	*TcpPerfStats

	/* Flow Geo Info */
	GeoEnd  uint8
	Country uint8
	Region  uint8
	ISP     uint8

	CloseType
	IsActiveService bool
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
	formatted += fmt.Sprintf("Exporter: %s ", IpFromUint32(f.Exporter))
	formatted += fmt.Sprintf("InPort: %d\n", f.InPort)
	formatted += fmt.Sprintf("\tMACSrc: %s ", Uint64ToMac(f.MACSrc))
	formatted += fmt.Sprintf("MACDst: %s ", Uint64ToMac(f.MACDst))
	formatted += fmt.Sprintf("IPSrc: %s ", IpFromUint32(f.IPSrc))
	formatted += fmt.Sprintf("IPDst: %s ", IpFromUint32(f.IPDst))
	formatted += fmt.Sprintf("Proto: %v ", f.Proto)
	formatted += fmt.Sprintf("PortSrc: %d ", f.PortSrc)
	formatted += fmt.Sprintf("PortDst: %d", f.PortDst)
	return formatted
}

func (f *FlowMetricsPeerSrc) String() string {
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

func (f *FlowMetricsPeerDst) String() string {
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
	formatted += fmt.Sprintf("CloseType: %d ", f.CloseType)
	formatted += fmt.Sprintf("TimeBitmap: %d ", f.TimeBitmap)
	formatted += fmt.Sprintf("StartTime: %d ", f.StartTime)
	formatted += fmt.Sprintf("CurStartTime: %d ", f.CurStartTime)
	formatted += fmt.Sprintf("EndTime: %d ", f.EndTime)
	formatted += fmt.Sprintf("Duration: %d\n", f.Duration)
	formatted += fmt.Sprintf("\tVLAN: %d ", f.VLAN)
	formatted += fmt.Sprintf("EthType: %d ", f.EthType)
	formatted += fmt.Sprintf("Country: %d ", f.Country)
	formatted += fmt.Sprintf("Region: %d ", f.Region)
	formatted += fmt.Sprintf("ISP: %d ", f.ISP)
	formatted += fmt.Sprintf("GeoEnd: %d ", f.GeoEnd)
	formatted += fmt.Sprintf("%s\n", f.FlowKey.String())
	formatted += fmt.Sprintf("\tFlowMetricsPeerSrc: {%s}\n", f.FlowMetricsPeerSrc.String())
	formatted += fmt.Sprintf("\tFlowMetricsPeerDst: {%s}", f.FlowMetricsPeerDst.String())
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
