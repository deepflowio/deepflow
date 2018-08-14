package datatype

import (
	"time"

	"github.com/google/gopacket/layers"
)

type Metering struct {
	Exporter     IP
	Timestamp    time.Duration
	InPort0      uint32
	VLAN         uint16
	IPSrc        IP
	IPDst        IP
	Proto        layers.IPProtocol
	PortSrc      uint16
	PortDst      uint16
	ByteCount0   uint64
	ByteCount1   uint64
	PacketCount0 uint64
	PacketCount1 uint64
	L3EpcID0     uint32
	L3EpcID1     uint32
}
