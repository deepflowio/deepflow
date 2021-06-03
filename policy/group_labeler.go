package policy

import (
	"net"
)

const (
	NAMED     = 0
	ANONYMOUS = 1
)

type IpGroupData struct {
	Id    uint32
	EpcId int32
	Type  uint8
	Ips   []string
	VmIds []uint32
}

type Ip6GroupItem struct {
	id    uint32
	ipNet *net.IPNet
}
