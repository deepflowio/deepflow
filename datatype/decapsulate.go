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
	TUNNEL_TYPE_ERSPAN
)

func (t TunnelType) String() string {
	if t == TUNNEL_TYPE_VXLAN {
		return "vxlan"
	} else if t == TUNNEL_TYPE_ERSPAN {
		return "erspan"
	}

	return "none"
}

type TunnelInfo struct {
	Src  IPv4Int
	Dst  IPv4Int
	Id   uint32
	Type TunnelType
}

func (t *TunnelInfo) String() string {
	return fmt.Sprintf("type: %s, src: %s, dst: %s, id: %d", t.Type, IpFromUint32(t.Src), IpFromUint32(t.Dst), t.Id)
}

func (t *TunnelInfo) Decapsulate(l3Packet []byte) int {
	t.Type = TUNNEL_TYPE_NONE
	// 通过ERSPANIII_HEADER_SIZE(12 bytes)+ERSPANIII_SUBHEADER_SIZE(8 bytes)判断，保证不会数组越界
	if len(l3Packet) < OFFSET_ERSPAN_VER+ERSPANIII_HEADER_SIZE+ERSPANIII_SUBHEADER_SIZE {
		return 0
	}
	_ = l3Packet[OFFSET_VXLAN_VNI-ETH_HEADER_SIZE] // early bound check hint

	assumeIpProtocol := IPProtocol(l3Packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE])
	assumeDPort := BigEndian.Uint16(l3Packet[OFFSET_DPORT-ETH_HEADER_SIZE:])
	assumeVxlanFlags := l3Packet[OFFSET_VXLAN_FLAGS-ETH_HEADER_SIZE]

	isUDP := assumeIpProtocol == IPProtocolUDP
	isVxlanUDP := isUDP && assumeDPort == 4789
	isVxlan := isVxlanUDP && assumeVxlanFlags == 0x8

	isGRE := assumeIpProtocol == IPProtocolGRE

	if !isVxlan && !isGRE {
		return 0
	}

	t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
	t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
	if isVxlan {
		t.Type = TUNNEL_TYPE_VXLAN
		t.Id = BigEndian.Uint32(l3Packet[OFFSET_VXLAN_VNI-ETH_HEADER_SIZE:]) >> 8
		// return offset start from L3
		return OFFSET_VXLAN_FLAGS - ETH_HEADER_SIZE + VXLAN_HEADER_SIZE
	} else {
		greProtocolType := BigEndian.Uint16(l3Packet[OFFSET_GRE_PROTOCOL_TYPE-ETH_HEADER_SIZE:])
		if greProtocolType == 0x88BE { // ERSPAN II
			t.Type = TUNNEL_TYPE_ERSPAN
			t.Id = BigEndian.Uint32(l3Packet[OFFSET_ERSPAN_VER-ETH_HEADER_SIZE:]) & 0x3ff
			return OFFSET_ERSPAN_VER - ETH_HEADER_SIZE + ERSPANII_HEADER_SIZE
		} else if greProtocolType == 0x22EB { // ERSPAN III
			t.Type = TUNNEL_TYPE_ERSPAN
			t.Id = BigEndian.Uint32(l3Packet[OFFSET_ERSPAN_VER-ETH_HEADER_SIZE:]) & 0x3ff
			oFlag := l3Packet[OFFSET_ERSPAN_VER-ETH_HEADER_SIZE+ERSPANIII_HEADER_SIZE-1] & 0x1
			if oFlag == 0 {
				return OFFSET_ERSPAN_VER - ETH_HEADER_SIZE + ERSPANIII_HEADER_SIZE
			} else {
				return OFFSET_ERSPAN_VER - ETH_HEADER_SIZE + ERSPANIII_HEADER_SIZE + ERSPANIII_SUBHEADER_SIZE
			}
		}
	}

	return 0
}

func (t *TunnelInfo) Valid() bool {
	return t.Type != TUNNEL_TYPE_NONE
}
