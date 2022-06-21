package datatype

import (
	"fmt"
	"time"

	"github.com/google/gopacket/layers"
)

type Metering struct { // FIXME: Deprecated!!!
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

func (m *Metering) String() string {
	return fmt.Sprintf("TIMESTAMP: %d INPORT: 0x%X VLAN: %d\n"+
		"    IP: %v -> %v PROTO: %d L3EpcID: %d -> %d PORT: %d -> %d\n"+
		"    ByteCount: %d -> %d PacketCount: %d -> %d",
		m.Timestamp, m.InPort0, m.VLAN,
		m.IPSrc, m.IPDst, m.Proto, m.L3EpcID0, m.L3EpcID1, m.PortSrc, m.PortDst,
		m.ByteCount0, m.ByteCount1, m.PacketCount0, m.PacketCount1)
}
