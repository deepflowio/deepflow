package datatype

import (
	"fmt"
	"reflect"
	"time"

	"github.com/google/gopacket/layers"
)

type CloseType uint8

const (
	unknownCloseType CloseType = iota
	TCPFin
	TCPRst
	Timeout
	Flood
	ForcedReport // 5
	ForcedClose
	HalfOpenTimeout
	HalfCloseTimeout
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
	Exporter IP
	/* L1 */
	InPort0 uint32
	/* L3 */
	IPSrc IP
	IPDst IP
	/* L4 */
	Proto   layers.IPProtocol
	PortSrc uint16
	PortDst uint16
	/* Tunnel */
	TunnelIPSrc uint32
	TunnelIPDst uint32
	TunnelID    uint32
	TunnelType  uint8
}

type TcpPerfStats struct {
	ARTAvg                 time.Duration
	RTTSyn                 time.Duration
	RTT                    time.Duration
	RTTAvg                 time.Duration
	SynRetransCount0       uint32
	SynRetransCount1       uint32
	RetransCount0          uint32
	RetransCount1          uint32
	TotalRetransCount      uint32
	ZeroWinCount0          uint32
	ZeroWinCount1          uint32
	TotalZeroWinCount      uint32
	PshUrgCount0           uint32
	PshUrgCount1           uint32
	TotalPshUrgCount       uint32
	PacketIntervalAvg      uint64
	PacketIntervalVariance uint64
	PacketSizeVariance     uint64
}

type Flow struct {
	FlowKey
	CloseType

	Host      IP
	FlowID    uint64
	StartTime time.Duration
	EndTime   time.Duration
	Duration  time.Duration

	/* L2 */
	VLAN    uint16
	EthType layers.EthernetType
	MACSrc  MACAddr
	MACDst  MACAddr

	/* L4 */
	TCPFlags0 uint16
	TCPFlags1 uint16

	/* Overlay */
	OverlayTunnelID   uint32
	OverlayTunnelType uint8

	/* L7 */

	/* Packet Counters */
	ByteCount0        uint64
	ByteCount1        uint64
	PacketCount0      uint64
	PacketCount1      uint64
	TotalByteCount0   uint64
	TotalByteCount1   uint64
	TotalPacketCount0 uint64
	TotalPacketCount1 uint64

	/* Timers */
	CurStartTime time.Duration
	ArrTime00    time.Duration
	ArrTime0Last time.Duration
	ArrTime10    time.Duration
	ArrTime1Last time.Duration

	/* Platform Data */
	SubnetID0 uint32
	SubnetID1 uint32

	L3DeviceType0 DeviceType
	L3DeviceType1 DeviceType
	L3DeviceID0   uint32
	L3DeviceID1   uint32
	L3EpcID0      int32
	L3EpcID1      int32
	Host0         uint32
	Host1         uint32

	EpcID0      int32
	EpcID1      int32
	DeviceType0 DeviceType
	DeviceType1 DeviceType
	DeviceID0   uint32
	DeviceID1   uint32
	IfIndex0    uint32
	IfIndex1    uint32
	IfType0     uint32
	IfType1     uint32

	IsL2End0 bool
	IsL2End1 bool
	IsL3End0 bool
	IsL3End1 bool

	/* TCP Perf Data */
	*TcpPerfStats
}

func (t *TcpPerfStats) String() string {
	var formatStr string
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
