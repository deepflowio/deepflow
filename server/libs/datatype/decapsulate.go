/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package datatype

import (
	. "encoding/binary"
	"fmt"
	"unsafe"

	. "github.com/google/gopacket/layers"

	pb "github.com/deepflowio/deepflow/message/trident"
	. "github.com/deepflowio/deepflow/server/libs/utils"
)

type TunnelType uint8

const (
	TUNNEL_TYPE_NONE          = TunnelType(pb.DecapType_DECAP_TYPE_NONE)
	TUNNEL_TYPE_VXLAN         = TunnelType(pb.DecapType_DECAP_TYPE_VXLAN)
	TUNNEL_TYPE_IPIP          = TunnelType(pb.DecapType_DECAP_TYPE_IPIP)
	TUNNEL_TYPE_TENCENT_GRE   = TunnelType(pb.DecapType_DECAP_TYPE_TENCENT) // GRE.ver=0/1 GRE.protoType=IPv4/IPv6
	TUNNEL_TYPE_ERSPAN_OR_TEB = TUNNEL_TYPE_TENCENT_GRE + 1

	LE_IPV4_PROTO_TYPE_I      = 0x0008 // 0x0008's LittleEndian
	LE_IPV6_PROTO_TYPE_I      = 0xDD86 // 0x86dd's LittleEndian
	LE_ERSPAN_PROTO_TYPE_II   = 0xBE88 // 0x88BE's LittleEndian
	LE_ERSPAN_PROTO_TYPE_III  = 0xEB22 // 0x22EB's LittleEndian
	LE_VXLAN_PROTO_UDP_DPORT  = 0xB512 // 0x12B5(4789)'s LittleEndian
	LE_VXLAN_PROTO_UDP_DPORT2 = 0x1821 // 0x2118(8472)'s LittleEndian
	LE_VXLAN_PROTO_UDP_DPORT3 = 0x801A // 0x1A80(6784)'s LittleEndian
	LE_TEB_PROTO              = 0x5865 // 0x6558(25944)'s LittleEndian
	VXLAN_FLAGS               = 8

	_TUNNEL_TIER_LIMIT = 2
)

var (
	tunnelTypeTips = [...]string{
		TUNNEL_TYPE_NONE:          "none",
		TUNNEL_TYPE_VXLAN:         "VXLAN",
		TUNNEL_TYPE_IPIP:          "IPIP",
		TUNNEL_TYPE_TENCENT_GRE:   "GRE",
		TUNNEL_TYPE_ERSPAN_OR_TEB: "ERSPAN_TEB",
	}
)

func (t TunnelType) String() string {
	return tunnelTypeTips[t]
}

type TunnelTypeBitmap uint16

func NewTunnelTypeBitmap(items ...TunnelType) TunnelTypeBitmap {
	bitmap := TunnelTypeBitmap(0)
	for _, item := range items {
		bitmap |= (1 << TunnelTypeBitmap(item))
	}
	return bitmap
}

func (b *TunnelTypeBitmap) Add(tunnelType TunnelType) {
	*b |= 1 << TunnelTypeBitmap(tunnelType)
}

func (b TunnelTypeBitmap) Has(tunnelType TunnelType) bool {
	return (b & (1 << TunnelTypeBitmap(tunnelType))) != 0
}

func (b TunnelTypeBitmap) IsEmpty() bool {
	return b == 0
}

func (b TunnelTypeBitmap) String() string {
	context := ""
	for i := TunnelType(0); i <= TUNNEL_TYPE_ERSPAN_OR_TEB; i++ {
		if b.Has(i) {
			context += tunnelTypeTips[i]
		}
	}
	return context
}

type TunnelInfo struct {
	Src    IPv4Int
	Dst    IPv4Int
	MacSrc uint32 // lowest 4B
	MacDst uint32 // lowest 4B
	Id     uint32
	Type   TunnelType
	Tier   uint8
	IsIPv6 bool
}

func (t *TunnelInfo) String() string {
	return fmt.Sprintf(
		"type: %s, src: %s %08x, dst: %s %08x, id: %d, tier: %d",
		t.Type, IpFromUint32(t.Src), t.MacSrc, IpFromUint32(t.Dst), t.MacDst, t.Id, t.Tier)
}

func (t *TunnelInfo) DecapsulateVxlan(packet []byte, l2Len int) int {
	l3Packet := packet[l2Len:]
	if len(l3Packet) < OFFSET_VXLAN_FLAGS+VXLAN_HEADER_SIZE {
		return 0
	}
	dstPort := *(*uint16)(unsafe.Pointer(&l3Packet[OFFSET_DPORT-ETH_HEADER_SIZE]))
	if dstPort != LE_VXLAN_PROTO_UDP_DPORT &&
		dstPort != LE_VXLAN_PROTO_UDP_DPORT2 &&
		dstPort != LE_VXLAN_PROTO_UDP_DPORT3 {
		return 0
	}
	if l3Packet[OFFSET_VXLAN_FLAGS-ETH_HEADER_SIZE] != VXLAN_FLAGS {
		return 0
	}

	// 仅保存最外层的隧道信息
	if t.Tier == 0 {
		t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
		t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
		t.MacSrc = BigEndian.Uint32(packet[OFFSET_SA_LOW4B:])
		t.MacDst = BigEndian.Uint32(packet[OFFSET_DA_LOW4B:])
		t.Type = TUNNEL_TYPE_VXLAN
		t.Id = BigEndian.Uint32(l3Packet[OFFSET_VXLAN_VNI-ETH_HEADER_SIZE:]) >> 8
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

func (t *TunnelInfo) DecapsulateErspan(packet []byte, l2Len int, flags, greProtocolType uint16, ipHeaderSize int) int {
	l3Packet := packet[l2Len:]
	switch greProtocolType {
	case LE_ERSPAN_PROTO_TYPE_II:
		if flags == 0 { // ERSPAN I
			// 仅保存最外层的隧道信息
			if t.Tier == 0 {
				t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
				t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
				t.MacSrc = BigEndian.Uint32(packet[OFFSET_SA_LOW4B:])
				t.MacDst = BigEndian.Uint32(packet[OFFSET_DA_LOW4B:])
				t.Type = TUNNEL_TYPE_ERSPAN_OR_TEB
			}
			t.Tier++
			return ipHeaderSize + GRE_HEADER_SIZE + ERSPANI_HEADER_SIZE
		} else { // ERSPAN II
			// 仅保存最外层的隧道信息
			greHeaderSize := GRE_HEADER_SIZE + t.calcGreOptionSize(flags)
			if t.Tier == 0 {
				t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
				t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
				t.MacSrc = BigEndian.Uint32(packet[OFFSET_SA_LOW4B:])
				t.MacDst = BigEndian.Uint32(packet[OFFSET_DA_LOW4B:])
				t.Type = TUNNEL_TYPE_ERSPAN_OR_TEB
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
			t.MacSrc = BigEndian.Uint32(packet[OFFSET_SA_LOW4B:])
			t.MacDst = BigEndian.Uint32(packet[OFFSET_DA_LOW4B:])
			t.Type = TUNNEL_TYPE_ERSPAN_OR_TEB
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

func (t *TunnelInfo) DecapsulateTencentGre(packet []byte, l2Len int, flags, greProtocolType uint16, ipHeaderSize int) int {
	// TCE GRE：Version 0、Version 1两种
	if flags&GRE_FLAGS_VER_MASK > 1 || flags&GRE_FLAGS_KEY_MASK == 0 { // 未知的GRE
		return 0
	}
	greHeaderSize := GRE_HEADER_SIZE + t.calcGreOptionSize(flags)
	greKeyOffset := GRE_KEY_OFFSET
	if flags&GRE_FLAGS_CSUM_MASK != 0 {
		greKeyOffset += GRE_CSUM_LEN
	}
	l3Packet := packet[l2Len:]
	// 仅保存最外层的隧道信息
	if t.Tier == 0 {
		t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
		t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
		t.MacSrc = BigEndian.Uint32(packet[OFFSET_SA_LOW4B:])
		t.MacDst = BigEndian.Uint32(packet[OFFSET_DA_LOW4B:])
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

func (t *TunnelInfo) DecapsulateTeb(packet []byte, l2Len int, flags, greProtocolType uint16, ipHeaderSize int) int {
	if flags&GRE_FLAGS_VER_MASK != 0 || flags&GRE_FLAGS_KEY_MASK == 0 { // 未知的GRE
		return 0
	}
	greHeaderSize := GRE_HEADER_SIZE + t.calcGreOptionSize(flags)
	greKeyOffset := GRE_KEY_OFFSET
	if flags&GRE_FLAGS_CSUM_MASK != 0 {
		greKeyOffset += GRE_CSUM_LEN
	}
	l3Packet := packet[l2Len:]
	// 仅保存最外层的隧道信息
	if t.Tier == 0 {
		t.Src = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:]))
		t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:]))
		t.MacSrc = BigEndian.Uint32(packet[OFFSET_SA_LOW4B:])
		t.MacDst = BigEndian.Uint32(packet[OFFSET_DA_LOW4B:])
		t.Type = TUNNEL_TYPE_ERSPAN_OR_TEB
		t.Id = BigEndian.Uint32(l3Packet[ipHeaderSize+greKeyOffset:])
	}

	t.Tier++
	return greHeaderSize + ipHeaderSize
}

func (t *TunnelInfo) DecapsulateGre(packet []byte, l2Len int, tunnelTypeBitmap TunnelTypeBitmap) int {
	l3Packet := packet[l2Len:]
	ipHeaderSize := int((l3Packet[IP_IHL_OFFSET] & 0xf) << 2)
	flags := BigEndian.Uint16(l3Packet[ipHeaderSize+GRE_FLAGS_OFFSET:])
	greProtocolType := *(*uint16)(unsafe.Pointer(&l3Packet[ipHeaderSize+GRE_PROTOCOL_OFFSET]))
	if tunnelTypeBitmap.Has(TUNNEL_TYPE_ERSPAN_OR_TEB) &&
		(greProtocolType == LE_ERSPAN_PROTO_TYPE_II || greProtocolType == LE_ERSPAN_PROTO_TYPE_III) { // ERSPAN
		return t.DecapsulateErspan(packet, l2Len, flags, greProtocolType, ipHeaderSize)
	} else if tunnelTypeBitmap.Has(TUNNEL_TYPE_TENCENT_GRE) &&
		(greProtocolType == LE_IPV4_PROTO_TYPE_I || greProtocolType == LE_IPV6_PROTO_TYPE_I) {
		return t.DecapsulateTencentGre(packet, l2Len, flags, greProtocolType, ipHeaderSize)
	} else if tunnelTypeBitmap.Has(TUNNEL_TYPE_ERSPAN_OR_TEB) &&
		greProtocolType == LE_TEB_PROTO {
		return t.DecapsulateTeb(packet, l2Len, flags, greProtocolType, ipHeaderSize)
	}
	return 0
}

func (t *TunnelInfo) Decapsulate(packet []byte, l2Len int, tunnelTypeBitmap TunnelTypeBitmap) int {
	if tunnelTypeBitmap.IsEmpty() {
		return 0
	}
	if t.Tier == _TUNNEL_TIER_LIMIT {
		return 0
	}
	// 通过ERSPANIII_HEADER_SIZE(12 bytes)+ERSPANIII_SUBHEADER_SIZE(8 bytes)判断，保证不会数组越界
	l3Packet := packet[l2Len:]
	if len(l3Packet) < IP_HEADER_SIZE+GRE_HEADER_SIZE+ERSPANIII_HEADER_SIZE+ERSPANIII_SUBHEADER_SIZE {
		return 0
	}

	offset := 0
	protocol := IPProtocol(l3Packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE])
	if protocol == IPProtocolUDP {
		if tunnelTypeBitmap.Has(TUNNEL_TYPE_VXLAN) {
			offset = t.DecapsulateVxlan(packet, l2Len)
		}
	} else if protocol == IPProtocolGRE {
		offset = t.DecapsulateGre(packet, l2Len, tunnelTypeBitmap)
	} else if protocol == IPProtocolIPv4 {
		if tunnelTypeBitmap.Has(TUNNEL_TYPE_IPIP) {
			offset = t.DecapsulateIPIP(packet, l2Len, false, false)
		}
	} else if protocol == IPProtocolIPv6 {
		if tunnelTypeBitmap.Has(TUNNEL_TYPE_IPIP) {
			offset = t.DecapsulateIPIP(packet, l2Len, false, true)
		}
	}

	return offset
}

func (t *TunnelInfo) Decapsulate6Vxlan(packet []byte, l2Len int) int {
	l3Packet := packet[l2Len:]
	if len(l3Packet) < OFFSET_VXLAN_FLAGS+VXLAN_HEADER_SIZE {
		return 0
	}
	dstPort := *(*uint16)(unsafe.Pointer(&l3Packet[IP6_HEADER_SIZE+UDP_DPORT_OFFSET]))
	if dstPort != LE_VXLAN_PROTO_UDP_DPORT &&
		dstPort != LE_VXLAN_PROTO_UDP_DPORT2 &&
		dstPort != LE_VXLAN_PROTO_UDP_DPORT3 {
		return 0
	}
	if l3Packet[IP6_HEADER_SIZE+UDP_HEADER_SIZE+VXLAN_FLAGS_OFFSET] != VXLAN_FLAGS {
		return 0
	}

	// 仅保存最外层的隧道信息
	if t.Tier == 0 {
		t.Src = IPv4Int(BigEndian.Uint32(l3Packet[IP6_SIP_OFFSET:]))
		t.Dst = IPv4Int(BigEndian.Uint32(l3Packet[IP6_DIP_OFFSET:]))
		t.MacSrc = BigEndian.Uint32(packet[OFFSET_SA_LOW4B:])
		t.MacDst = BigEndian.Uint32(packet[OFFSET_DA_LOW4B:])
		t.Type = TUNNEL_TYPE_VXLAN
		t.Id = BigEndian.Uint32(l3Packet[IP6_HEADER_SIZE+UDP_HEADER_SIZE+VXLAN_VNI_OFFSET:]) >> 8
		t.IsIPv6 = true
	}
	t.Tier++

	// return offset start from L3
	return IP6_HEADER_SIZE + UDP_HEADER_SIZE + VXLAN_HEADER_SIZE
}

func (t *TunnelInfo) Decapsulate6(packet []byte, l2Len int, tunnelTypeBitmap TunnelTypeBitmap) int {
	if tunnelTypeBitmap.IsEmpty() {
		return 0
	}
	if t.Tier == _TUNNEL_TIER_LIMIT {
		return 0
	}

	l3Packet := packet[l2Len:]
	// 通过ERSPANIII_HEADER_SIZE(12 bytes)+ERSPANIII_SUBHEADER_SIZE(8 bytes)判断，保证不会数组越界
	if len(l3Packet) < IP6_HEADER_SIZE+GRE_HEADER_SIZE+ERSPANIII_HEADER_SIZE+ERSPANIII_SUBHEADER_SIZE {
		return 0
	}
	offset := 0
	protocol := IPProtocol(l3Packet[IP6_PROTO_OFFSET])
	if protocol == IPProtocolUDP {
		if tunnelTypeBitmap.Has(TUNNEL_TYPE_VXLAN) {
			offset = t.Decapsulate6Vxlan(packet, l2Len)
		}
	} else if protocol == IPProtocolIPv4 {
		if tunnelTypeBitmap.Has(TUNNEL_TYPE_IPIP) {
			offset = t.DecapsulateIPIP(packet, l2Len, true, false)
		}
	} else if protocol == IPProtocolIPv6 {
		if tunnelTypeBitmap.Has(TUNNEL_TYPE_IPIP) {
			offset = t.DecapsulateIPIP(packet, l2Len, true, true)
		}
	}

	return offset
}

func (t *TunnelInfo) Valid() bool {
	return t.Type != TUNNEL_TYPE_NONE
}

func (t *TunnelInfo) DecapsulateIPIP(packet []byte, l2Len int, underlayIpv6, overlayIpv6 bool) int {
	l3Packet := packet[l2Len:]
	underlayIpHeaderSize := int((l3Packet[IP_IHL_OFFSET] & 0xf) << 2)
	if underlayIpv6 { // underlay网络为IPv6时不支持Options字段
		underlayIpHeaderSize = IP6_HEADER_SIZE
	}

	if t.Tier == 0 {
		if underlayIpv6 {
			t.Src = BigEndian.Uint32(l3Packet[IP6_SIP_OFFSET:])
			t.Dst = BigEndian.Uint32(l3Packet[IP6_DIP_OFFSET:])
			t.MacSrc = BigEndian.Uint32(packet[OFFSET_SA_LOW4B:])
			t.MacDst = BigEndian.Uint32(packet[OFFSET_DA_LOW4B:])
			t.IsIPv6 = true
		} else {
			t.Src = BigEndian.Uint32(l3Packet[OFFSET_SIP-ETH_HEADER_SIZE:])
			t.Dst = BigEndian.Uint32(l3Packet[OFFSET_DIP-ETH_HEADER_SIZE:])
			t.MacSrc = BigEndian.Uint32(packet[OFFSET_SA_LOW4B:])
			t.MacDst = BigEndian.Uint32(packet[OFFSET_DA_LOW4B:])
		}
		t.Type = TUNNEL_TYPE_IPIP
		t.Id = 0
	}
	t.Tier++

	// 去除underlay ip头，将l2层头放在overlay ip头前

	// 偏移计算：overlay ip头开始位置(l2Len + underlayIpHeaderSize) - l2层长度(l2Len)
	start := l2Len + underlayIpHeaderSize - l2Len
	copy(packet[start:], packet[:l2Len])
	if !overlayIpv6 {
		BigEndian.PutUint16(packet[start+l2Len-2:], uint16(EthernetTypeIPv4))
	} else {
		BigEndian.PutUint16(packet[start+l2Len-2:], uint16(EthernetTypeIPv6))
	}
	// l2已经做过解析，这个去除掉已经解析的l2长度
	return start - l2Len
}
