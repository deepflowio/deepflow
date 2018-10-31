package datatype

import (
	"time"
)

const (
	MASK_LEN        = 32
	MIN_MASK_LEN    = 1
	MAX_MASK_LEN    = 32
	IF_TYPE_WAN     = 3
	NETMASK         = 0xFFFFFFFF
	DATA_VALID_TIME = 1 * time.Minute
	ARP_VALID_TIME  = 1 * time.Hour
)

type IpNet struct {
	Ip       uint32
	Netmask  uint32
	SubnetId uint32
}

type PlatformData struct {
	Mac        uint64
	Ips        []*IpNet
	EpcId      int32
	DeviceType uint32
	DeviceId   uint32
	IfIndex    uint32
	IfType     uint32
	HostIp     uint32
	GroupIds   []uint32
}
