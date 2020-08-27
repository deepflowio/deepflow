package datatype

import (
	. "encoding/binary"
	"fmt"
	"unsafe"

	. "github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

type TunnelType uint8

const (
	TUNNEL_TYPE_NONE TunnelType = iota
	TUNNEL_TYPE_VXLAN
	TUNNEL_TYPE_ERSPAN
	TUNNEL_TYPE_TENCENT_GRE // GRE.ver=1 GRE.protoType=IPv4/IPv6

	LE_IPV4_PROTO_TYPE_I     = 0x0008 // 0x0008's LittleEndian
	LE_IPV6_PROTO_TYPE_I     = 0xDD86 // 0x86dd's LittleEndian
	LE_ERSPAN_PROTO_TYPE_II  = 0xBE88 // 0x88BE's LittleEndian
	LE_ERSPAN_PROTO_TYPE_III = 0xEB22 // 0x22EB's LittleEndian
	LE_VXLAN_PROTO_UDP_DPORT = 0xB512 // 0x12B5(4789)'s LittleEndian
	VXLAN_FLAGS              = 8
)

func (t TunnelType) String() string {
	if t == TUNNEL_TYPE_VXLAN {
		return "vxlan"
	} else if t == TUNNEL_TYPE_ERSPAN {
		return "erspan"
	} else if t == TUNNEL_TYPE_TENCENT_GRE {
		return "tencent-gre"
	}

	return "none"
}

type TunnelInfo struct {
	Src  IPv4Int
	Dst  IPv4Int
	Id   uint32
	Type TunnelType
}

func (t *TunnelInfo) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU32(t.Src)
	encoder.WriteU32(t.Dst)
	encoder.WriteU32(t.Id)
	encoder.WriteU8(uint8(t.Type))
}

func (t *TunnelInfo) Decode(decoder *codec.SimpleDecoder) {
	t.Src = decoder.ReadU32()
	t.Dst = decoder.ReadU32()
	t.Id = decoder.ReadU32()
	t.Type = TunnelType(decoder.ReadU8())
}

func (t *TunnelInfo) String() string {
	return fmt.Sprintf("type: %s, src: %s, dst: %s, id: %d", t.Type, IpFromUint32(t.Src), IpFromUint32(t.Dst), t.Id)
}

func (t *TunnelInfo) DecapsulateVxlan(l3Packet []byte) int {
	if len(l3Packet) < OFFSET_VXLAN_FLAGS+VXLAN_HEADER_SIZE {
		return 0
	}

	if *(*uint16)(unsafe.Pointer(&l3Packet[OFFSET_DPORT-ETH_HEADER_SIZE])) != LE_VXLAN_PROTO_UDP_DPORT {
		return 0
	}
	if l3Packet[OFFSET_VXLAN_FLAGS-ETH_HEADER_SIZE] != VXLAN_FLAGS {
		return 0
	}

	t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
	t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
	t.Type = TUNNEL_TYPE_VXLAN
	t.Id = BigEndian.Uint32(l3Packet[OFFSET_VXLAN_VNI-ETH_HEADER_SIZE:]) >> 8
	// return offset start from L3
	return OFFSET_VXLAN_FLAGS - ETH_HEADER_SIZE + VXLAN_HEADER_SIZE
}

func (t *TunnelInfo) DecapsulateGre(l3Packet []byte) int {
	greProtocolType := *(*uint16)(unsafe.Pointer(&l3Packet[OFFSET_GRE_PROTOCOL_TYPE-ETH_HEADER_SIZE]))
	if greProtocolType == LE_ERSPAN_PROTO_TYPE_II { // ERSPAN II
		t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
		t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
		t.Type = TUNNEL_TYPE_ERSPAN
		t.Id = BigEndian.Uint32(l3Packet[OFFSET_ERSPAN_VER-ETH_HEADER_SIZE:]) & 0x3ff
		return OFFSET_ERSPAN_VER - ETH_HEADER_SIZE + ERSPANII_HEADER_SIZE
	} else if greProtocolType == LE_ERSPAN_PROTO_TYPE_III { // ERSPAN III
		t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
		t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
		t.Type = TUNNEL_TYPE_ERSPAN
		t.Id = BigEndian.Uint32(l3Packet[OFFSET_ERSPAN_VER-ETH_HEADER_SIZE:]) & 0x3ff
		oFlag := l3Packet[OFFSET_ERSPAN_VER-ETH_HEADER_SIZE+ERSPANIII_HEADER_SIZE-1] & 0x1
		if oFlag == 0 {
			return OFFSET_ERSPAN_VER - ETH_HEADER_SIZE + ERSPANIII_HEADER_SIZE
		} else {
			return OFFSET_ERSPAN_VER - ETH_HEADER_SIZE + ERSPANIII_HEADER_SIZE + ERSPANIII_SUBHEADER_SIZE
		}
	} else if greProtocolType == LE_IPV4_PROTO_TYPE_I || greProtocolType == LE_IPV6_PROTO_TYPE_I {
		flags := BigEndian.Uint16(l3Packet[OFFSET_GRE_FLAGS-ETH_HEADER_SIZE:])
		if flags&GRE_FLAGS_VER_MASK != 1 || flags&GRE_FLAGS_KEY_MASK == 0 { // 未知的GRE
			return 0
		}
		tunnelHeader := GRE_HEADER_SIZE
		greKeyOffset := OFFSET_GRE_KEY - ETH_HEADER_SIZE
		t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
		t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
		t.Type = TUNNEL_TYPE_TENCENT_GRE
		if flags&GRE_FLAGS_CSUM_MASK != 0 {
			tunnelHeader += GRE_CSUM_LEN
			greKeyOffset += GRE_CSUM_LEN
		}
		t.Id = BigEndian.Uint32(l3Packet[greKeyOffset:])
		if flags&GRE_FLAGS_SEQ_MASK != 0 {
			tunnelHeader += GRE_SEQ_LEN
		}
		overlayOffset := tunnelHeader + IP_HEADER_SIZE - ETH_HEADER_SIZE // 这里伪造L2层信息

		// NOTICE:
		//     这里需要将TunnelID封装为Mac Suffix，策略FastPath需要不同的MAC区分不同的VPC。
		// 腾讯GRE流量是通过TunnelID来确认其对应的EPC ID的，这个将TunnelID用作MAC后缀，同
		// 样能在FastPath里面区分不同的VPC
		srcMacSuffix, dstMacSuffix := [2]byte{}, [2]byte{}
		copy(srcMacSuffix[:], l3Packet[greKeyOffset:greKeyOffset+2])
		copy(dstMacSuffix[:], l3Packet[greKeyOffset+2:greKeyOffset+4])

		// 目的MAC
		copy(l3Packet[overlayOffset:], []byte{0, 0, 0, 0})
		copy(l3Packet[overlayOffset+4:], dstMacSuffix[:])
		// 源MAC
		copy(l3Packet[overlayOffset+MAC_ADDR_LEN:], []byte{0, 0, 0, 0})
		copy(l3Packet[overlayOffset+MAC_ADDR_LEN+4:], srcMacSuffix[:])

		if greProtocolType == LE_IPV4_PROTO_TYPE_I {
			copy(l3Packet[overlayOffset+MAC_ADDR_LEN*2:], []byte{0x8, 0x0})
		} else {
			copy(l3Packet[overlayOffset+MAC_ADDR_LEN*2:], []byte{0x86, 0xdd})
		}
		return overlayOffset
	}
	return 0
}

func (t *TunnelInfo) Decapsulate(l3Packet []byte) int {
	t.Type = TUNNEL_TYPE_NONE
	// 通过ERSPANIII_HEADER_SIZE(12 bytes)+ERSPANIII_SUBHEADER_SIZE(8 bytes)判断，保证不会数组越界
	if len(l3Packet) < OFFSET_ERSPAN_VER+ERSPANIII_HEADER_SIZE+ERSPANIII_SUBHEADER_SIZE {
		return 0
	}

	switch IPProtocol(l3Packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE]) {
	case IPProtocolUDP:
		if *(*uint16)(unsafe.Pointer(&l3Packet[OFFSET_DPORT-ETH_HEADER_SIZE])) != LE_VXLAN_PROTO_UDP_DPORT {
			return 0
		}
		if l3Packet[OFFSET_VXLAN_FLAGS-ETH_HEADER_SIZE] != VXLAN_FLAGS {
			return 0
		}

		t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
		t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
		t.Type = TUNNEL_TYPE_VXLAN
		t.Id = BigEndian.Uint32(l3Packet[OFFSET_VXLAN_VNI-ETH_HEADER_SIZE:]) >> 8
		// return offset start from L3
		return OFFSET_VXLAN_FLAGS - ETH_HEADER_SIZE + VXLAN_HEADER_SIZE
	case IPProtocolGRE:
		return t.DecapsulateGre(l3Packet)
	default:
		return 0
	}

	return 0
}

func (t *TunnelInfo) Valid() bool {
	return t.Type != TUNNEL_TYPE_NONE
}
