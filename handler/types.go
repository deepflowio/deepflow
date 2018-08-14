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
	TunnelId   uint32
	TunnelType TunnelType
}

type PacketFlag uint16

func (f PacketFlag) IsSet(flag PacketFlag) bool {
	return f&flag != 0
}

const (
	CFLAG_MAC0 PacketFlag = 1 << iota
	CFLAG_MAC1
	CFLAG_VLANTAG
	CFLAG_HEADER_TYPE

	CFLAG_IP0
	CFLAG_IP1
	CFLAG_PORT0
	CFLAG_PORT1

	CFLAG_TTL
	CFLAG_FLAGS_FRAG_OFFSET
	CFLAG_DATAOFF_IHL
	CFLAG_WIN

	CFLAG_TCP_FLAGS
	PFLAG_SRC_ENDPOINT
	PFLAG_DST_ENDPOINT
	PFLAG_TUNNEL

	PFLAG_NONE PacketFlag = 0
	CFLAG_FULL            = 0x1FFF
)
