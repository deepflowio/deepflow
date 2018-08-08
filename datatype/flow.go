package datatype

import (
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
	TunID    uint64
	TunIPSrc uint32
	TunIPDst uint32
	TunType  uint64
}

type TcpPerfStat struct {
	ARTAvg            uint64
	RTTSyn            uint64
	RTT               uint64
	RTTAvg            uint64
	SynRetransCnt0    uint64
	SynRetransCnt1    uint64
	RetransCnt0       uint64
	RetransCnt1       uint64
	TotalRetransCnt   uint64
	ZeroWndCnt0       uint64
	ZeroWndCnt1       uint64
	TotalZeroWndCnt   uint64
	SlowStartCnt0     uint64
	SlowStartCnt1     uint64
	TotalSlowStartCnt uint64
	PshUrgCnt0        uint64
	PshUrgCnt1        uint64
	TotalPshUrgCnt    uint64
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
	TCPSynSeq uint32
	ICMPID    uint32

	/* Overlay */
	OverlayTunID   uint64
	OverlayTunType uint32

	/* L7 */

	/* Packet Counters */
	ByteCnt0      uint64
	ByteCnt1      uint64
	PktCnt0       uint64
	PktCnt1       uint64
	TotalByteCnt0 uint64
	TotalByteCnt1 uint64
	TotalPktCnt0  uint64
	TotalPktCnt1  uint64

	/* Timers */
	CurStartTime time.Duration
	ArrTime00    time.Duration
	ArrTime0Last time.Duration
	ArrTime10    time.Duration
	ArrTime1Last time.Duration

	/* Fragment Counters */
	FragByteCnt0      uint64
	FragByteCnt1      uint64
	FragPktCnt0       uint64
	FragPktCnt1       uint64
	TotalFragByteCnt0 uint64
	TotalFragByteCnt1 uint64
	TotalFragPktCnt0  uint64
	TotalFragPktCnt1  uint64

	/* Platform Data */
	SubnetID0 uint32
	SubnetID1 uint32

	L3DeviceType0 DeviceType
	L3DeviceType1 DeviceType
	L3DeviceID0   uint32
	L3DeviceID1   uint32
	L3EpcID0      int32
	L3EpcID1      int32

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
	*TcpPerfStat
}
