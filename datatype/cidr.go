package datatype

import (
	"net"

	"gitlab.x.lan/yunshan/message/trident"
)

const (
	CIDR_TYPE_WAN = uint8(trident.CidrType_WAN)
	CIDR_TYPE_LAN = uint8(trident.CidrType_LAN)
)

type Cidr struct {
	IpNet    *net.IPNet
	EpcId    int32
	Type     uint8
	TunnelId uint32
}
