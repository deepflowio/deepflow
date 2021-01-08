package datatype

import (
	. "encoding/binary"
	"fmt"
	"unsafe"

	. "github.com/google/gopacket/layers"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
	pb "gitlab.x.lan/yunshan/message/trident"
)

type TunnelType uint8

const (
	TUNNEL_TYPE_NONE   = TunnelType(pb.DecapType_DECAP_TYPE_NONE)
	TUNNEL_TYPE_VXLAN  = TunnelType(pb.DecapType_DECAP_TYPE_VXLAN)
	TUNNEL_TYPE_ERSPAN = TunnelType(pb.DecapType_DECAP_TYPE_ERSPAN)
	// GRE.ver=1 GRE.protoType=IPv4/IPv6
	TUNNEL_TYPE_TENCENT_GRE = TunnelType(pb.DecapType_DECAP_TYPE_TENCENT)
	TUNNEL_TYPE_VXLAN_VXLAN = TunnelType(pb.DecapType_DECAP_TYPE_VXLAN_VXLAN)

	LE_IPV4_PROTO_TYPE_I      = 0x0008 // 0x0008's LittleEndian
	LE_IPV6_PROTO_TYPE_I      = 0xDD86 // 0x86dd's LittleEndian
	LE_ERSPAN_PROTO_TYPE_II   = 0xBE88 // 0x88BE's LittleEndian
	LE_ERSPAN_PROTO_TYPE_III  = 0xEB22 // 0x22EB's LittleEndian
	LE_VXLAN_PROTO_UDP_DPORT  = 0xB512 // 0x12B5(4789)'s LittleEndian
	LE_VXLAN_PROTO_UDP_DPORT2 = 0x1821 // 0x2118(8472)'s LittleEndian
	VXLAN_FLAGS               = 8
)

func (t TunnelType) String() string {
	if t == TUNNEL_TYPE_VXLAN {
		return "vxlan"
	} else if t == TUNNEL_TYPE_ERSPAN {
		return "erspan"
	} else if t == TUNNEL_TYPE_TENCENT_GRE {
		return "tencent-gre"
	} else if t == TUNNEL_TYPE_VXLAN_VXLAN {
		return "vxlan-vxlan"
	}

	return "none"
}

type TunnelInfo struct {
	Src  IPv4Int
	Dst  IPv4Int
	Id   uint32
	Type TunnelType
	Tier uint8
}

func (t *TunnelInfo) String() string {
	return fmt.Sprintf("type: %s, src: %s, dst: %s, id: %d", t.Type, IpFromUint32(t.Src), IpFromUint32(t.Dst), t.Id)
}

func (t *TunnelInfo) DecapsulateVxlan(l3Packet []byte) int {
	if len(l3Packet) < OFFSET_VXLAN_FLAGS+VXLAN_HEADER_SIZE {
		return 0
	}
	dstPort := *(*uint16)(unsafe.Pointer(&l3Packet[OFFSET_DPORT-ETH_HEADER_SIZE]))
	if dstPort != LE_VXLAN_PROTO_UDP_DPORT && dstPort != LE_VXLAN_PROTO_UDP_DPORT2 {
		return 0
	}
	if l3Packet[OFFSET_VXLAN_FLAGS-ETH_HEADER_SIZE] != VXLAN_FLAGS {
		return 0
	}

	// 仅保存最外层的隧道信息
	if t.Tier == 0 {
		t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
		t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
		t.Type = TUNNEL_TYPE_VXLAN
		t.Id = BigEndian.Uint32(l3Packet[OFFSET_VXLAN_VNI-ETH_HEADER_SIZE:]) >> 8
	} else {
		t.Type = TUNNEL_TYPE_VXLAN_VXLAN
	}
	t.Tier++
	// return offset start from L3
	return OFFSET_VXLAN_FLAGS - ETH_HEADER_SIZE + VXLAN_HEADER_SIZE
}

func (t *TunnelInfo) calcGreOptionSize(flags uint16) int {
	size := 0
	if flags&GRE_FLAGS_KEY_MASK != 0 {
		size += GRE_KEY_LEN
	}
	if flags&GRE_FLAGS_SEQ_MASK != 0 {
		size += GRE_SEQ_LEN
	}
	if flags&GRE_FLAGS_CSUM_MASK != 0 {
		size += GRE_CSUM_LEN
	}
	return size
}

func (t *TunnelInfo) DecapsulateGre(l3Packet []byte) int {
	ipHeaderSize := int((l3Packet[IP_IHL_OFFSET] & 0xf) << 2)
	flags := BigEndian.Uint16(l3Packet[ipHeaderSize+GRE_FLAGS_OFFSET:])
	greProtocolType := *(*uint16)(unsafe.Pointer(&l3Packet[ipHeaderSize+GRE_PROTOCOL_OFFSET]))
	if greProtocolType == LE_ERSPAN_PROTO_TYPE_II { // ERSPAN II && ERSPAN I
		if flags == 0 { // ERSPAN I
			// 仅保存最外层的隧道信息
			if t.Tier == 0 {
				t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
				t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
				t.Type = TUNNEL_TYPE_ERSPAN
			}
			t.Tier++
			return ipHeaderSize + GRE_HEADER_SIZE + ERSPANI_HEADER_SIZE
		} else { // ERSPAN II
			// 仅保存最外层的隧道信息
			greHeaderSize := GRE_HEADER_SIZE + t.calcGreOptionSize(flags)
			if t.Tier == 0 {
				t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
				t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
				t.Type = TUNNEL_TYPE_ERSPAN
				t.Id = BigEndian.Uint32(l3Packet[ipHeaderSize+greHeaderSize+ERSPAN_ID_OFFSET:]) & 0x3ff
			}
			t.Tier++
			return ipHeaderSize + greHeaderSize + ERSPANII_HEADER_SIZE
		}
	} else if greProtocolType == LE_ERSPAN_PROTO_TYPE_III { // ERSPAN III
		greHeaderSize := GRE_HEADER_SIZE + t.calcGreOptionSize(flags)
		// 仅保存最外层的隧道信息
		if t.Tier == 0 {
			t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
			t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
			t.Type = TUNNEL_TYPE_ERSPAN
			t.Id = BigEndian.Uint32(l3Packet[ipHeaderSize+greHeaderSize+ERSPAN_ID_OFFSET:]) & 0x3ff
		}
		t.Tier++
		oFlag := l3Packet[ipHeaderSize+greHeaderSize+ERSPANIII_FLAGS_OFFSET] & 0x1
		if oFlag == 0 {
			return ipHeaderSize + greHeaderSize + ERSPANIII_HEADER_SIZE
		} else {
			return ipHeaderSize + greHeaderSize + ERSPANIII_HEADER_SIZE + ERSPANIII_SUBHEADER_SIZE
		}
	} else if greProtocolType == LE_IPV4_PROTO_TYPE_I || greProtocolType == LE_IPV6_PROTO_TYPE_I {
		if flags&GRE_FLAGS_VER_MASK != 1 || flags&GRE_FLAGS_KEY_MASK == 0 { // 未知的GRE
			return 0
		}
		greHeaderSize := GRE_HEADER_SIZE + t.calcGreOptionSize(flags)
		greKeyOffset := GRE_KEY_OFFSET
		if flags&GRE_FLAGS_CSUM_MASK != 0 {
			greKeyOffset += GRE_CSUM_LEN
		}
		// 仅保存最外层的隧道信息
		if t.Tier == 0 {
			t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
			t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
			t.Type = TUNNEL_TYPE_TENCENT_GRE
			t.Id = BigEndian.Uint32(l3Packet[ipHeaderSize+greKeyOffset:])
		}
		t.Tier++
		overlayOffset := greHeaderSize + ipHeaderSize - ETH_HEADER_SIZE // 这里伪造L2层信息

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

func (t *TunnelInfo) Decapsulate(l3Packet []byte, tunnelType TunnelType) int {
	if tunnelType == TUNNEL_TYPE_NONE {
		return 0
	}
	t.Type = TUNNEL_TYPE_NONE
	// 通过ERSPANIII_HEADER_SIZE(12 bytes)+ERSPANIII_SUBHEADER_SIZE(8 bytes)判断，保证不会数组越界
	if len(l3Packet) < IP_HEADER_SIZE+GRE_HEADER_SIZE+ERSPANIII_HEADER_SIZE+ERSPANIII_SUBHEADER_SIZE {
		return 0
	}
	protocol := IPProtocol(l3Packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE])
	if protocol == IPProtocolUDP && (tunnelType == TUNNEL_TYPE_VXLAN || tunnelType == TUNNEL_TYPE_VXLAN_VXLAN) {
		return t.DecapsulateVxlan(l3Packet)
	} else if protocol == IPProtocolGRE && (tunnelType == TUNNEL_TYPE_TENCENT_GRE || tunnelType == TUNNEL_TYPE_ERSPAN) {
		return t.DecapsulateGre(l3Packet)
	}
	return 0
}

func (t *TunnelInfo) Decapsulate6Vxlan(l3Packet []byte) int {
	if len(l3Packet) < OFFSET_VXLAN_FLAGS+VXLAN_HEADER_SIZE {
		return 0
	}
	dstPort := *(*uint16)(unsafe.Pointer(&l3Packet[IP6_HEADER_SIZE+UDP_DPORT_OFFSET]))
	if dstPort != LE_VXLAN_PROTO_UDP_DPORT && dstPort != LE_VXLAN_PROTO_UDP_DPORT2 {
		return 0
	}
	if l3Packet[IP6_HEADER_SIZE+UDP_HEADER_SIZE+VXLAN_FLAGS_OFFSET] != VXLAN_FLAGS {
		return 0
	}

	// 仅保存最外层的隧道信息
	if t.Tier == 0 {
		t.Src = IPv4Int(BigEndian.Uint32(l3Packet[IP6_SIP_OFFSET:]))
		t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[IP6_DIP_OFFSET:]))
		t.Type = TUNNEL_TYPE_VXLAN
		t.Id = BigEndian.Uint32(l3Packet[IP6_HEADER_SIZE+UDP_HEADER_SIZE+VXLAN_VNI_OFFSET:]) >> 8
	} else {
		t.Type = TUNNEL_TYPE_VXLAN_VXLAN
	}
	t.Tier++
	// return offset start from L3
	return IP6_HEADER_SIZE + UDP_HEADER_SIZE + VXLAN_HEADER_SIZE
}

func (t *TunnelInfo) Decapsulate6(l3Packet []byte, tunnelType TunnelType) int {
	if tunnelType == TUNNEL_TYPE_NONE {
		return 0
	}
	t.Type = TUNNEL_TYPE_NONE
	// 通过ERSPANIII_HEADER_SIZE(12 bytes)+ERSPANIII_SUBHEADER_SIZE(8 bytes)判断，保证不会数组越界
	if len(l3Packet) < IP6_HEADER_SIZE+GRE_HEADER_SIZE+ERSPANIII_HEADER_SIZE+ERSPANIII_SUBHEADER_SIZE {
		return 0
	}
	protocol := IPProtocol(l3Packet[IP6_PROTO_OFFSET])
	if protocol == IPProtocolUDP && (tunnelType == TUNNEL_TYPE_VXLAN || tunnelType == TUNNEL_TYPE_VXLAN_VXLAN) {
		return t.Decapsulate6Vxlan(l3Packet)
	}
	return 0
}

func (t *TunnelInfo) Valid() bool {
	return t.Type != TUNNEL_TYPE_NONE
}
