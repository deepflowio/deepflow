package datatype

import (
	"net"
)

type Cidr struct {
	IpNet *net.IPNet
	EpcId int32
	Type  uint8
}
