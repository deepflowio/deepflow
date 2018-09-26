package datatype

import (
	"fmt"
	"reflect"
	"time"

	"github.com/google/gopacket/layers"
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
	Proto   layers.IPProtocol
	PortSrc uint16
	PortDst uint16
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
	RTTSyn time.Duration
	RTT    time.Duration
	ART    time.Duration
	TcpPerfCountsPeerSrc
	TcpPerfCountsPeerDst
	TotalRetransCount      uint32
	TotalZeroWinCount      uint32
	TotalPshUrgCount       uint32
	PacketIntervalAvg      uint64
	PacketIntervalVariance uint64
	PacketSizeVariance     uint64
}

type FlowMetricsPeer struct {
	TCPFlags         uint8
	ByteCount        uint64
	PacketCount      uint64
	TotalByteCount   uint64
	TotalPacketCount uint64
	ArrTime0         time.Duration
	ArrTimeLast      time.Duration
	SubnetID         uint32
	L3DeviceType     DeviceType
	L3DeviceID       uint32
	L3EpcID          int32
	Host             uint32
	EpcID            int32
	DeviceType       DeviceType
	DeviceID         uint32
	IfIndex          uint32
	IfType           uint32
	IsL2End          bool
	IsL3End          bool
}

type FlowMetricsPeerSrc FlowMetricsPeer

type FlowMetricsPeerDst FlowMetricsPeer

type Flow struct {
	FlowKey
	CloseType
	FlowMetricsPeerSrc
	FlowMetricsPeerDst

	FlowID     uint64
	TimeBitmap uint64

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
}

func (t *TcpPerfStats) String() string {
	var formatStr string

	if t == nil {
		return ""
	}

	typeOf := reflect.TypeOf(*t)
	valueOf := reflect.ValueOf(*t)
	for i := 0; i < typeOf.NumField(); i++ {
		formatStr += fmt.Sprintf("%v: %v ", typeOf.Field(i).Name, valueOf.Field(i))
	}
	return formatStr
}

func (f *FlowKey) String() string {
	var formatStr string
	typeOf := reflect.TypeOf(*f)
	valueOf := reflect.ValueOf(*f)
	for i := 0; i < typeOf.NumField(); i++ {
		formatStr += fmt.Sprintf("%v: %v ", typeOf.Field(i).Name, valueOf.Field(i))
	}
	return formatStr
}

func (f *FlowMetricsPeer) String() string {
	var formatStr string
	typeOf := reflect.TypeOf(*f)
	valueOf := reflect.ValueOf(*f)
	for i := 0; i < typeOf.NumField(); i++ {
		formatStr += fmt.Sprintf("%v: %v ", typeOf.Field(i).Name, valueOf.Field(i))
	}
	return formatStr
}

func (f *Flow) String() string {
	formatted := ""
	typeOf := reflect.TypeOf(*f)
	valueOf := reflect.ValueOf(*f)
	for i := 0; i < typeOf.NumField(); i++ {
		field := typeOf.Field(i)
		value := valueOf.Field(i)
		if v := value.MethodByName("String"); v.IsValid() {
			results := v.Call([]reflect.Value{})
			formatted += results[0].String()
		} else {
			formatted += fmt.Sprintf("%v: %v ", field.Name, value)
		}
	}
	return formatted
}
