package handler

import (
	"net"
)

type TunnelType uint8

const (
	TUNNEL_TYPE_NONE TunnelType = iota
	TUNNEL_TYPE_VXLAN
)

func (t TunnelType) String() string {
	return "vxlan"
}

type TunnelInfo struct {
	TunnelSrc  net.IP
	TunnelDst  net.IP
	TunnelType TunnelType
	TunnelId   uint32
}
