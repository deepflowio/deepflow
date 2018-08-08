package datatype

import (
	"github.com/google/gopacket/layers"
	"time"
)

type Metering struct {
	Exporter  IP
	Timestamp time.Duration
	InPort0   uint32
	VLAN      uint16
	IPSrc     IP
	IPDst     IP
	Proto     layers.IPProtocol
	PortSrc   uint16
	PortDst   uint16
	ByteCnt0  uint64
	ByteCnt1  uint64
	PktCnt0   uint64
	PktCnt1   uint64
	L3EpcID0  uint32
	L3EpcID1  uint32
}
