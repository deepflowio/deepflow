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

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	TAPPORT_FROM_LOCAL_MAC   = iota
	TAPPORT_FROM_GATEWAY_MAC // 专有云NFV网关镜像流量
	TAPPORT_FROM_TUNNEL_IPV4 // 交换机ERSPAN镜像流量
	TAPPORT_FROM_TUNNEL_IPV6 // 交换机ERSPAN镜像流量
	TAPPORT_FROM_ID          // 其他镜像流量（dispatcher id）
	TAPPORT_FROM_NETFLOW
	TAPPORT_FROM_SFLOW
	TAPPORT_FROM_EBPF
	TAPPORT_FROM_OTEL
)

const (
	_FROM_OFFSET        = 60
	_TUNNEL_TYPE_OFFSET = 32
	_NAT_SOURCE_OFFSET  = 36
	_RESERVED_OFFSET    = 40

	_RESERVED_MASK    = 0xfffff
	_TUNNEL_TYPE_MASK = 0xf
	_NAT_SOURCE_MASK  = 0xf
)

type NATSource uint8

const (
	NAT_SOURCE_NONE NATSource = iota
	NAT_SOURCE_VIP
	NAT_SOURCE_TOA
)

func (n NATSource) String() string {
	switch n {
	case NAT_SOURCE_NONE:
		return "none"
	case NAT_SOURCE_VIP:
		return "VIP"
	case NAT_SOURCE_TOA:
		return "TOA"
	default:
		return "NATSource unknown"
	}
}

// 64     60         40           36         32                                    0
// +------+----------+------------+----------+-------------------------------------+
// | from | RESERVED | NAT SOURCE | TUN_TYPE |              ip/id/mac              |
// +------+----------+------------+----------+-------------------------------------+
// 注意ip/id/mac不能超过32bit，否则数据存储、四元组聚合都会有歧义
type TapPort uint64

func FromLocalMAC(tunnelType TunnelType, mac uint32) TapPort {
	return TapPort(mac) | TapPort(tunnelType)<<_TUNNEL_TYPE_OFFSET | TAPPORT_FROM_LOCAL_MAC<<_FROM_OFFSET
}

func FromNetFlow(mac uint32) TapPort {
	return TapPort(mac) | TAPPORT_FROM_NETFLOW<<_FROM_OFFSET
}

func FromSFlow(mac uint32) TapPort {
	return TapPort(mac) | TAPPORT_FROM_SFLOW<<_FROM_OFFSET
}

func FromGatewayMAC(tunnelType TunnelType, mac uint32) TapPort {
	return TapPort(mac) | TapPort(tunnelType)<<_TUNNEL_TYPE_OFFSET | TAPPORT_FROM_GATEWAY_MAC<<_FROM_OFFSET
}

func FromTunnelIP(ip uint32, isIPv6 bool) TapPort {
	tapPort := TapPort(ip)
	if !isIPv6 {
		tapPort |= TAPPORT_FROM_TUNNEL_IPV4 << _FROM_OFFSET
	} else {
		tapPort |= TAPPORT_FROM_TUNNEL_IPV6 << _FROM_OFFSET
	}
	return tapPort
}

func FromID(tunnelType TunnelType, id int) TapPort {
	return TapPort(id) | TapPort(tunnelType)<<_TUNNEL_TYPE_OFFSET | TAPPORT_FROM_ID<<_FROM_OFFSET
}

// TapPort、TapPortType、TunnelType
func (p TapPort) SplitToPortTypeTunnel() (uint32, uint8, NATSource, TunnelType) {
	return uint32(p), uint8(p >> _FROM_OFFSET), NATSource(p >> _NAT_SOURCE_OFFSET & _NAT_SOURCE_MASK), TunnelType(p >> _TUNNEL_TYPE_OFFSET & _TUNNEL_TYPE_MASK)
}

// 用于编码后做为Map Key
func (p TapPort) SetReservedBytes(v uint32) TapPort {
	return p | TapPort(v&_RESERVED_MASK)<<_RESERVED_OFFSET
}

func (p TapPort) String() string {
	tapPort, tapPortType, _, tunnelType := p.SplitToPortTypeTunnel()
	switch tapPortType {
	case TAPPORT_FROM_LOCAL_MAC:
		return fmt.Sprintf("LMAC@%s@%02x:%02x:%02x:%02x",
			tunnelType, uint8(tapPort>>24), uint8(tapPort>>16), uint8(tapPort>>8), uint8(tapPort))
	case TAPPORT_FROM_GATEWAY_MAC:
		return fmt.Sprintf("GMAC@%s@%02x:%02x:%02x:%02x",
			tunnelType, uint8(tapPort>>24), uint8(tapPort>>16), uint8(tapPort>>8), uint8(tapPort))
	case TAPPORT_FROM_TUNNEL_IPV4:
		return fmt.Sprintf("IPv4@%s", utils.IpFromUint32(tapPort))
	case TAPPORT_FROM_TUNNEL_IPV6:
		return fmt.Sprintf("IPv6@0x%08x", tapPort)
	case TAPPORT_FROM_ID:
		return fmt.Sprintf("ID@%s@%d", tunnelType, tapPort)
	case TAPPORT_FROM_NETFLOW:
		return fmt.Sprintf("NetFlow@%d", tapPort)
	case TAPPORT_FROM_SFLOW:
		return fmt.Sprintf("SFlow@%d", tapPort)
	default:
		panic(fmt.Sprintf("Invalid TapPort type is %d.", tapPortType))
	}
}
