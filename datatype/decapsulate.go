package datatype

import (
	. "encoding/binary"
	"fmt"
	"unsafe"

	. "github.com/google/gopacket/layers"
	. "gitlab.yunshan.net/yunshan/droplet-libs/utils"
	pb "gitlab.yunshan.net/yunshan/message/trident"
)

type TunnelType uint16

const (
	// 0~5 bit 表示第一层隧道，6~12 bit表示第二层隧道
	TUNNEL_TYPE_NONE        = TunnelType(pb.DecapType_DECAP_TYPE_NONE)
	TUNNEL_TYPE_VXLAN       = TunnelType(pb.DecapType_DECAP_TYPE_VXLAN)
	TUNNEL_TYPE_IPIP        = TunnelType(pb.DecapType_DECAP_TYPE_IPIP)
	TUNNEL_TYPE_TENCENT_GRE = TunnelType(pb.DecapType_DECAP_TYPE_TENCENT)     // GRE.ver=1 GRE.protoType=IPv4/IPv6
	TUNNEL_TYPE_VXLAN_VXLAN = TunnelType(pb.DecapType_DECAP_TYPE_VXLAN_VXLAN) // (DECAP_TYPE_VXLAN << 6) | DECAP_TYPE_VXLAN
	TUNNEL_TYPE_VXLAN_IPIP  = TunnelType(pb.DecapType_DECAP_TYPE_VXLAN_IPIP)  // (DECAP_TYPE_VXLAN << 6) | DECAP_TYPE_IPIP
	TUNNEL_TYPE_ERSPAN      = 0xffff

	LE_IPV4_PROTO_TYPE_I      = 0x0008 // 0x0008's LittleEndian
	LE_IPV6_PROTO_TYPE_I      = 0xDD86 // 0x86dd's LittleEndian
	LE_ERSPAN_PROTO_TYPE_II   = 0xBE88 // 0x88BE's LittleEndian
	LE_ERSPAN_PROTO_TYPE_III  = 0xEB22 // 0x22EB's LittleEndian
	LE_VXLAN_PROTO_UDP_DPORT  = 0xB512 // 0x12B5(4789)'s LittleEndian
	LE_VXLAN_PROTO_UDP_DPORT2 = 0x1821 // 0x2118(8472)'s LittleEndian
	VXLAN_FLAGS               = 8

	TUNNEL_TYPE_TIER1_MASK  = 0x3f
	TUNNEL_TYPE_TIER2_SHIFT = 6
)

func (t TunnelType) String() string {
	if t == TUNNEL_TYPE_VXLAN {
		return "vxlan"
	} else if t == TUNNEL_TYPE_TENCENT_GRE {
		return "tencent-gre"
	} else if t == TUNNEL_TYPE_VXLAN_VXLAN {
		return "vxlan-vxlan"
	} else if t == TUNNEL_TYPE_IPIP {
		return "ipip"
	} else if t == TUNNEL_TYPE_VXLAN_IPIP {
		return "vxlan-ipip"
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
	return fmt.Sprintf("type: %s, src: %s, dst: %s, id: %d, tier: %d", t.Type, IpFromUint32(t.Src), IpFromUint32(t.Dst), t.Id, t.Tier)
}

func (t *TunnelInfo) DecapsulateVxlan(packet []byte, l2Len int, tunnelType TunnelType) int {
	l3Packet := packet[l2Len:]
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
	} else { // VXLAN-VXLAN
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

func (t *TunnelInfo) DecapsulateErspan(l3Packet []byte, flags, greProtocolType uint16, ipHeaderSize int) int {
	switch greProtocolType {
	case LE_ERSPAN_PROTO_TYPE_II:
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
	case LE_ERSPAN_PROTO_TYPE_III: // ERSPAN III
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
	default:
		return 0
	}
	return 0
}

func IsGrePseudoInnerMac(mac uint64) bool {
	return mac>>16 == 0
}

func (t *TunnelInfo) DecapsulateTencentGre(l3Packet []byte, flags, greProtocolType uint16, ipHeaderSize int) int {
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
	// 样能在FastPath里面区分不同的VPC。
	//     这样的伪造MAC可以通过IsGrePseudoInnerMac函数判断
	srcMacSuffix, dstMacSuffix := [2]byte{}, [2]byte{}
	copy(srcMacSuffix[:], l3Packet[ipHeaderSize+greKeyOffset:ipHeaderSize+greKeyOffset+2])
	copy(dstMacSuffix[:], l3Packet[ipHeaderSize+greKeyOffset+2:ipHeaderSize+greKeyOffset+4])

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

func (t *TunnelInfo) DecapsulateGre(l3Packet []byte, decapErspan, decapTencentGre bool) int {
	ipHeaderSize := int((l3Packet[IP_IHL_OFFSET] & 0xf) << 2)
	flags := BigEndian.Uint16(l3Packet[ipHeaderSize+GRE_FLAGS_OFFSET:])
	greProtocolType := *(*uint16)(unsafe.Pointer(&l3Packet[ipHeaderSize+GRE_PROTOCOL_OFFSET]))
	if decapErspan && (greProtocolType == LE_ERSPAN_PROTO_TYPE_II || greProtocolType == LE_ERSPAN_PROTO_TYPE_III) { // ERSPAN
		return t.DecapsulateErspan(l3Packet, flags, greProtocolType, ipHeaderSize)
	} else if decapTencentGre && (greProtocolType == LE_IPV4_PROTO_TYPE_I || greProtocolType == LE_IPV6_PROTO_TYPE_I) {
		return t.DecapsulateTencentGre(l3Packet, flags, greProtocolType, ipHeaderSize)
	}
	return 0
}

func (t *TunnelInfo) Decapsulate(packet []byte, l2Len int, tunnelType TunnelType, decapErspan bool) int {
	// 通过ERSPANIII_HEADER_SIZE(12 bytes)+ERSPANIII_SUBHEADER_SIZE(8 bytes)判断，保证不会数组越界
	l3Packet := packet[l2Len:]
	if len(l3Packet) < IP_HEADER_SIZE+GRE_HEADER_SIZE+ERSPANIII_HEADER_SIZE+ERSPANIII_SUBHEADER_SIZE {
		return 0
	}

	offset := 0
	protocol := IPProtocol(l3Packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE])
	if protocol == IPProtocolUDP {
		if (tunnelType&TUNNEL_TYPE_TIER1_MASK == TUNNEL_TYPE_VXLAN) || (tunnelType>>TUNNEL_TYPE_TIER2_SHIFT == TUNNEL_TYPE_VXLAN) {
			offset = t.DecapsulateVxlan(packet, l2Len, tunnelType)
		}
	} else if protocol == IPProtocolGRE {
		offset = t.DecapsulateGre(l3Packet, decapErspan, tunnelType&TUNNEL_TYPE_TIER1_MASK == TUNNEL_TYPE_TENCENT_GRE)
	} else if protocol == IPProtocolIPv4 {
		if tunnelType&TUNNEL_TYPE_TIER1_MASK == TUNNEL_TYPE_IPIP {
			offset = t.DecapsulateIPIP(packet, l2Len, IP_HEADER_SIZE)
		}
	} else if protocol == IPProtocolIPv6 {
		if tunnelType&TUNNEL_TYPE_TIER1_MASK == TUNNEL_TYPE_IPIP {
			offset = t.Decapsulate6IPIP(packet, l2Len, IP_HEADER_SIZE)
		}
	}

	return offset
}

func (t *TunnelInfo) Decapsulate6Vxlan(packet []byte, l2Len int, tunnelType TunnelType) int {
	l3Packet := packet[l2Len:]
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
	} else { // VXLAN-VXLAN
		t.Type = TUNNEL_TYPE_VXLAN_VXLAN
	}
	t.Tier++

	// return offset start from L3
	return IP6_HEADER_SIZE + UDP_HEADER_SIZE + VXLAN_HEADER_SIZE
}

func (t *TunnelInfo) Decapsulate6(packet []byte, l2Len int, tunnelType TunnelType) int {
	if tunnelType == TUNNEL_TYPE_NONE {
		return 0
	}

	l3Packet := packet[l2Len:]
	t.Type = TUNNEL_TYPE_NONE
	// 通过ERSPANIII_HEADER_SIZE(12 bytes)+ERSPANIII_SUBHEADER_SIZE(8 bytes)判断，保证不会数组越界
	if len(l3Packet) < IP6_HEADER_SIZE+GRE_HEADER_SIZE+ERSPANIII_HEADER_SIZE+ERSPANIII_SUBHEADER_SIZE {
		return 0
	}
	offset := 0
	protocol := IPProtocol(l3Packet[IP6_PROTO_OFFSET])
	if protocol == IPProtocolUDP {
		if (tunnelType&TUNNEL_TYPE_TIER1_MASK == TUNNEL_TYPE_VXLAN) || (tunnelType>>TUNNEL_TYPE_TIER2_SHIFT == TUNNEL_TYPE_VXLAN) {
			offset = t.Decapsulate6Vxlan(packet, l2Len, tunnelType)
		}
	} else if protocol == IPProtocolIPv4 {
		if tunnelType&TUNNEL_TYPE_TIER1_MASK == TUNNEL_TYPE_IPIP {
			offset = t.DecapsulateIPIP(packet, l2Len, IP6_HEADER_SIZE)
		}
	} else if protocol == IPProtocolIPv6 {
		if tunnelType&TUNNEL_TYPE_TIER1_MASK == TUNNEL_TYPE_IPIP {
			offset = t.Decapsulate6IPIP(packet, l2Len, IP6_HEADER_SIZE)
		}
	}

	return offset
}

func (t *TunnelInfo) Valid() bool {
	return t.Type != TUNNEL_TYPE_NONE
}

func (t *TunnelInfo) DecapsulateIPIP(packet []byte, l2Len int, size int) int {
	l3Packet := packet[l2Len:]

	if t.Tier == 0 {
		if size == IP6_HEADER_SIZE {
			t.Src = BigEndian.Uint32(l3Packet[IP6_SIP_OFFSET:])
			t.Dst = BigEndian.Uint32(l3Packet[IP6_DIP_OFFSET:])
		} else {
			t.Src = BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:])
			t.Dst = BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:])
		}
		t.Type = TUNNEL_TYPE_IPIP
		t.Id = 0
	} else {
		t.Type = TUNNEL_TYPE_VXLAN_IPIP
	}
	t.Tier++

	if size == IP_HEADER_SIZE {
		copy(packet[IP_HEADER_SIZE:], packet[:ETH_HEADER_SIZE])
		BigEndian.PutUint16(packet[IP_HEADER_SIZE+MAC_ADDR_LEN*2:], uint16(EthernetTypeIPv4))
		return IP_HEADER_SIZE - ETH_HEADER_SIZE
	} else if size == IP6_HEADER_SIZE {
		copy(packet[IP6_HEADER_SIZE:], packet[:ETH_HEADER_SIZE])
		BigEndian.PutUint16(packet[IP6_HEADER_SIZE+MAC_ADDR_LEN*2:], uint16(EthernetTypeIPv4))
		return IP6_HEADER_SIZE - ETH_HEADER_SIZE
	}

	return 0
}

func (t *TunnelInfo) Decapsulate6IPIP(packet []byte, l2Len int, size int) int {
	l3Packet := packet[l2Len:]

	if t.Tier == 0 {
		if size == IP6_HEADER_SIZE {
			t.Src = BigEndian.Uint32(l3Packet[IP6_SIP_OFFSET:])
			t.Dst = BigEndian.Uint32(l3Packet[IP6_DIP_OFFSET:])
		} else {
			t.Src = BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:])
			t.Dst = BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:])
		}
		t.Type = TUNNEL_TYPE_IPIP
		t.Id = 0
	} else {
		t.Type = TUNNEL_TYPE_VXLAN_IPIP
	}
	t.Tier++

	if size == IP_HEADER_SIZE {
		copy(packet[IP_HEADER_SIZE:], packet[:ETH_HEADER_SIZE])
		BigEndian.PutUint16(packet[IP_HEADER_SIZE+MAC_ADDR_LEN*2:], uint16(EthernetTypeIPv6))
		return IP_HEADER_SIZE - ETH_HEADER_SIZE
	} else if size == IP6_HEADER_SIZE {
		copy(packet[IP6_HEADER_SIZE:], packet[:ETH_HEADER_SIZE])
		BigEndian.PutUint16(packet[IP6_HEADER_SIZE+MAC_ADDR_LEN*2:], uint16(EthernetTypeIPv6))
		return IP6_HEADER_SIZE - ETH_HEADER_SIZE
	}

	return 0
}
