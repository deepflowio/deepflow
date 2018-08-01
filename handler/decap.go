package handler

import (
	. "encoding/binary"
	"net"

	. "github.com/google/gopacket/layers"
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

func (i *TunnelInfo) Decapsulate(packet []byte) int {
	i.TunnelType = TUNNEL_TYPE_NONE
	// 通过长度判断是否是VxLAN的同时保证不会数组越界
	if len(packet) < OFFSET_VXLAN_FLAGS+VXLAN_HEADER_SIZE+ETH_HEADER_SIZE {
		return 0
	}
	vlanTagSize := 0
	ethType := EthernetType(BigEndian.Uint16(packet[OFFSET_ETH_TYPE:]))
	if ethType == EthernetTypeDot1Q {
		vlanTagSize = 4
		ethType = EthernetType(BigEndian.Uint16(packet[OFFSET_ETH_TYPE+4:]))
		packet = packet[vlanTagSize:]
	}

	_ = packet[OFFSET_VXLAN_VNI] // early bound check hint

	assumeIpProtocol := IPProtocol(packet[OFFSET_IP_PROTOCOL])
	assumeDPort := BigEndian.Uint16(packet[OFFSET_DPORT:])
	assumeVxlanFlags := packet[OFFSET_VXLAN_FLAGS]

	isIpv4 := ethType == EthernetTypeIPv4
	isUdp := assumeIpProtocol == IPProtocolUDP
	c1 := isIpv4 && isUdp // compiler hint
	isVxlanUdpPort := assumeDPort == 4789
	validVxlanFlags := assumeVxlanFlags == 0x8
	c2 := isVxlanUdpPort && validVxlanFlags
	c3 := c1 && c2
	if !c3 {
		return 0
	}
	i.TunnelSrc = packet[OFFSET_SIP:]
	i.TunnelDst = packet[OFFSET_DIP:]
	i.TunnelType = TUNNEL_TYPE_VXLAN
	i.TunnelId = BigEndian.Uint32(packet[OFFSET_VXLAN_VNI:]) >> 8
	return OFFSET_VXLAN_FLAGS + VXLAN_HEADER_SIZE
}
