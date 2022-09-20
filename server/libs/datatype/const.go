/*
 * Copyright (c) 2022 Yunshan Networks
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

type HeaderType uint8

const HEADER_TYPE_INVALID HeaderType = 0

const HEADER_TYPE_L2 HeaderType = 0x1
const (
	HEADER_TYPE_ETH = HEADER_TYPE_L2 + iota
	HEADER_TYPE_ARP
)

const HEADER_TYPE_L3 = 0x20
const (
	HEADER_TYPE_IPV4 = HEADER_TYPE_L3 + iota
	HEADER_TYPE_IPV4_ICMP
)

const HEADER_TYPE_IPV6_L3 = 0x40
const (
	HEADER_TYPE_IPV6 = HEADER_TYPE_IPV6_L3 + iota
)

const HEADER_TYPE_L4 = 0x80
const (
	HEADER_TYPE_IPV4_TCP = HEADER_TYPE_L4 + iota
	HEADER_TYPE_IPV4_UDP
)

const HEADER_TYPE_IPV6_L4 = 0xb0
const (
	HEADER_TYPE_IPV6_TCP = HEADER_TYPE_IPV6_L4 + iota
	HEADER_TYPE_IPV6_UDP
)

const (
	PACKET_SOURCE_ISP   uint32 = 0x10000
	PACKET_SOURCE_SPINE        = 0x20000
	PACKET_SOURCE_TOR          = 0x30000
)

const (
	MAC_ADDR_LEN               = 6
	VLANTAG_LEN                = 2
	HEADER_TYPE_LEN            = 1
	PORT_LEN                   = 2
	IP_ADDR_LEN                = 4
	ETH_TYPE_LEN               = 2
	IPV4_TTL_LEN               = 1
	IPV4_PROTO_LEN             = 1
	IPV4_FLAGS_FRAG_OFFSET_LEN = 2
	TCP_WIN_LEN                = 2
	TUNNEL_TYPE_LEN            = 1
	TUNNEL_ID_LEN              = 3

	MAX_TCP_OPTION_SIZE = 40

	ETH_HEADER_SIZE          = MAC_ADDR_LEN*2 + ETH_TYPE_LEN
	ARP_HEADER_SIZE          = 28
	VXLAN_HEADER_SIZE        = 8
	IP_HEADER_SIZE           = 20
	IP6_HEADER_SIZE          = 40
	UDP_HEADER_SIZE          = 8
	GRE_HEADER_SIZE          = 4
	ERSPANI_HEADER_SIZE      = 0
	ERSPANII_HEADER_SIZE     = 8
	ERSPANIII_HEADER_SIZE    = 12
	ERSPANIII_SUBHEADER_SIZE = 8

	MIN_IPV4_HEADER_SIZE = 20
	MIN_TCP_HEADER_SIZE  = 20
	ICMP_HEADER_SIZE     = 8

	TCP_OPT_WIN_SCALE_LEN = 3
	TCP_OPT_MSS_LEN       = 4

	LAYER_TUNNEL_SIZE = IP_ADDR_LEN*2 + TUNNEL_TYPE_LEN + TUNNEL_ID_LEN
	LAYER_L2_SIZE     = HEADER_TYPE_LEN + MAC_ADDR_LEN*2 + VLANTAG_LEN
	LAYER_L3_SIZE     = IP_ADDR_LEN*2 + 6 // DATAOFF_IHL(1B) + ID...TTL(5B)
)

const (
	OFFSET_DA          = 0
	OFFSET_DA_LOW4B    = 2
	OFFSET_SA          = OFFSET_DA + MAC_ADDR_LEN
	OFFSET_SA_LOW4B    = OFFSET_DA + MAC_ADDR_LEN + 2
	OFFSET_ETH_TYPE    = OFFSET_SA + MAC_ADDR_LEN
	OFFSET_IP_PROTOCOL = 23
	OFFSET_SIP         = 26
	OFFSET_DIP         = 30
	OFFSET_DPORT       = 36
	OFFSET_VXLAN_FLAGS = 42
	OFFSET_VXLAN_VNI   = 46
)

const (
	GRE_FLAGS_OFFSET    = 0
	GRE_PROTOCOL_OFFSET = 2
	GRE_KEY_OFFSET      = 4

	GRE_FLAGS_VER_MASK  = 0x7
	GRE_FLAGS_SEQ_MASK  = 1 << 12
	GRE_FLAGS_KEY_MASK  = 1 << 13
	GRE_FLAGS_CSUM_MASK = 1 << 15

	GRE_CSUM_LEN = 4 // csum + reserved1
	GRE_SEQ_LEN  = 4
	GRE_KEY_LEN  = 4
)

const (
	IP_IHL_OFFSET = 0

	IP6_PROTO_OFFSET = 6
	IP6_SIP_OFFSET   = 20 // 用于解析tunnel，仅使用后四个字节
	IP6_DIP_OFFSET   = 36 // 用于解析tunnel，仅使用后四个字节
	UDP_DPORT_OFFSET = 2

	VXLAN_FLAGS_OFFSET = 0
	VXLAN_VNI_OFFSET   = 4

	ERSPAN_ID_OFFSET       = 0 // erspan2和3共用，4字节取0x3ff
	ERSPANIII_FLAGS_OFFSET = 11
)

const (
	TCP_OPT_FLAG_WIN_SCALE   = 1 << iota // 0000 0001
	TCP_OPT_FLAG_MSS                     // 0000 0010
	TCP_OPT_FLAG_SACK_PERMIT             // 0000 0100
	TCP_OPT_FLAG_SACK        = 0x38      // 0011 1000, 同时也表示SACK的字节数，不要修改
)

const (
	IPV4_FRAG_DONT_FRAGMENT = 0x4000
	IPV4_FRAG_MORE_FRAGMENT = 0x2000
	IPV4_FRAG_OFFSET_MASK   = 0x1fff
)

const (
	L7PROTOCOL_LOG_RESP_CODE_NONE = -32768
)

func (t HeaderType) IsL3() bool {
	return t < HEADER_TYPE_L4
}

func (t HeaderType) IsIpv6() bool {
	return t == HEADER_TYPE_IPV6 || t == HEADER_TYPE_IPV6_TCP || t == HEADER_TYPE_IPV6_UDP
}
