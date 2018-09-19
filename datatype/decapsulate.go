package datatype

import (
	. "encoding/binary"
	"fmt"

	. "github.com/google/gopacket/layers"

	. "gitlab.x.lan/yunshan/droplet-libs/utils"
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
	Type TunnelType
	Src  IPv4Int
	Dst  IPv4Int
	Id   uint32
}

func (t *TunnelInfo) String() string {
	return fmt.Sprintf("type: %s, src: %s, dst: %s, id: %d", t.Type, IpFromUint32(t.Src), IpFromUint32(t.Dst), t.Id)
}

func (t *TunnelInfo) Decapsulate(l3Packet []byte) int {
	t.Type = TUNNEL_TYPE_NONE
	// 通过长度判断是否是VxLAN的同时保证不会数组越界
	if len(l3Packet) < OFFSET_VXLAN_FLAGS+VXLAN_HEADER_SIZE {
		return 0
	}
	_ = l3Packet[OFFSET_VXLAN_VNI-ETH_HEADER_SIZE] // early bound check hint

	assumeIpProtocol := IPProtocol(l3Packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE])
	assumeDPort := BigEndian.Uint16(l3Packet[OFFSET_DPORT-ETH_HEADER_SIZE:])
	assumeVxlanFlags := l3Packet[OFFSET_VXLAN_FLAGS-ETH_HEADER_SIZE]

	isUDP := assumeIpProtocol == IPProtocolUDP
	isVxlanUDP := isUDP && assumeDPort == 4789
	isVxlan := isVxlanUDP && assumeVxlanFlags == 0x8
	if !isVxlan {
		return 0
	}
	t.Type = TUNNEL_TYPE_VXLAN
	t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
	t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
	t.Id = BigEndian.Uint32(l3Packet[OFFSET_VXLAN_VNI-ETH_HEADER_SIZE:]) >> 8
	// return offset start from L3
	return OFFSET_VXLAN_FLAGS - ETH_HEADER_SIZE + VXLAN_HEADER_SIZE
}

func (t *TunnelInfo) Valid() bool {
	return t.Type != TUNNEL_TYPE_NONE
}
