package datatype

import (
	"net"

	"gitlab.yunshan.net/yunshan/message/trident"
)

const (
	CIDR_TYPE_WAN = uint8(trident.CidrType_WAN)
	CIDR_TYPE_LAN = uint8(trident.CidrType_LAN)
)

// IsVIP为true时不影响cidr epcid表的建立, 但是会单独建立VIP表
type Cidr struct {
	IpNet    *net.IPNet
	TunnelId uint32
	EpcId    int32
	Type     uint8
	IsVIP    bool
	RegionId uint32
}
