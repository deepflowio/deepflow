package datatype

import (
	"fmt"

	"gitlab.yunshan.net/yunshan/droplet-libs/utils"
)

const (
	TAPPORT_FROM_MAC = iota
	TAPPORT_FROM_IPV4
	TAPPORT_FROM_IPV6
	TAPPORT_FROM_ID // 专属类型采集器时使用dispatcher id
	TAPPORT_FROM_NETFLOW
	TAPPORT_FROM_SFLOW
)

const (
	_FROM_OFFSET = 60
)

// 64     60                                    0
// +------+-------------------------------------+
// | from |              ip/id/mac              |
// +------+-------------------------------------+
type TapPort uint64

func FromMAC(mac uint32) TapPort {
	return TapPort(mac) | TAPPORT_FROM_MAC<<_FROM_OFFSET
}

func FromNetFlow(mac uint32) TapPort {
	return TapPort(mac) | TAPPORT_FROM_NETFLOW<<_FROM_OFFSET
}

func FromSFlow(mac uint32) TapPort {
	return TapPort(mac) | TAPPORT_FROM_SFLOW<<_FROM_OFFSET
}

func FromIP(ip uint32, isIPv6 bool) TapPort {
	tapPort := TapPort(ip)
	if !isIPv6 {
		tapPort |= TAPPORT_FROM_IPV4 << _FROM_OFFSET
	} else {
		tapPort |= TAPPORT_FROM_IPV6 << _FROM_OFFSET
	}
	return tapPort
}

func FromID(id int) TapPort {
	return TapPort(id) | TAPPORT_FROM_ID<<_FROM_OFFSET
}

func (p TapPort) SplitToPortAndType() (uint32, uint8) {
	return uint32(p & 0xffffffff), uint8(p >> _FROM_OFFSET)
}

func (p TapPort) String() string {
	tapPort, tapPortType := p.SplitToPortAndType()
	switch tapPortType {
	case TAPPORT_FROM_MAC:
		return fmt.Sprintf("MAC@%02x:%02x:%02x:%02x",
			uint8(tapPort>>24), uint8(tapPort>>16), uint8(tapPort>>8), uint8(tapPort))
	case TAPPORT_FROM_IPV4:
		return fmt.Sprintf("IPv4@%s", utils.IpFromUint32(tapPort))
	case TAPPORT_FROM_IPV6:
		return fmt.Sprintf("IPv6@0x%08x", tapPort)
	case TAPPORT_FROM_ID:
		return fmt.Sprintf("ID@%d", tapPort)
	case TAPPORT_FROM_NETFLOW:
		return fmt.Sprintf("NetFlow@%d", tapPort)
	case TAPPORT_FROM_SFLOW:
		return fmt.Sprintf("SFlow@%d", tapPort)
	default:
		panic(fmt.Sprintf("Invalid TapPort type is %d.", tapPortType))
	}
}
