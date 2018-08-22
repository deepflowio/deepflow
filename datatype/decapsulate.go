package datatype

import (
	. "encoding/binary"

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
	Type TunnelType
	Src  IPv4Int
	Dst  IPv4Int
	Id   uint32
}

func (t *TunnelInfo) Decapsulate(packet []byte) int {
	t.Type = TUNNEL_TYPE_NONE
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

	isIPv4 := ethType == EthernetTypeIPv4
	isUDP := isIPv4 && assumeIpProtocol == IPProtocolUDP
	isVxlanUDP := isUDP && assumeDPort == 4789
	isVxlan := isVxlanUDP && assumeVxlanFlags == 0x8
	if !isVxlan {
		return 0
	}
	t.Type = TUNNEL_TYPE_VXLAN
	t.Src = IPv4Int(BigEndian.Uint32(packet[OFFSET_SIP:]))
	t.Dst = IPv4Int(BigEndian.Uint32(packet[OFFSET_DIP:]))
	t.Id = BigEndian.Uint32(packet[OFFSET_VXLAN_VNI:]) >> 8
	return OFFSET_VXLAN_FLAGS + VXLAN_HEADER_SIZE
}

func (t *TunnelInfo) Valid() bool {
	return t.Type != TUNNEL_TYPE_NONE
}
