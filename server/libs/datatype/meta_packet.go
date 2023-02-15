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
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	. "github.com/google/gopacket/layers"

	"github.com/deepflowio/deepflow/server/libs/pool"
	. "github.com/deepflowio/deepflow/server/libs/utils"
)

const VLAN_ID_MASK = uint16((1 << 12) - 1)
const MIRRORED_TRAFFIC = 7

type RawPacket = []byte

type MetaPacketTcpHeader struct {
	// 注意字节对齐!
	Seq           uint32
	Ack           uint32
	WinSize       uint16
	MSS           uint16
	Flags         uint8
	DataOffset    uint8
	WinScale      uint8
	SACKPermitted bool
	Sack          []byte // sack value
}

type PacketDirection uint8

const (
	CLIENT_TO_SERVER PacketDirection = FLOW_METRICS_PEER_SRC // 0
	SERVER_TO_CLIENT PacketDirection = FLOW_METRICS_PEER_DST // 1
)

func OppositePacketDirection(d PacketDirection) PacketDirection {
	return d ^ 1
}

type MetaPacket struct {
	// 注意字节对齐!
	RawHeader []byte // total packet
	RawIcmp   []byte // icmp header

	Timestamp    time.Duration
	EndpointData EndpointData
	PolicyData   PolicyData

	Tunnel *TunnelInfo

	PacketLen     uint16
	RawHeaderSize uint16
	VtapId        uint16
	TapType       TapType // (8B)
	TapPort       uint32
	L2End0        bool
	L2End1        bool
	L3End0        bool
	L3End1        bool // (8B)
	L3EpcId0      uint16
	L3EpcId1      uint16
	QueueHash     uint8

	MacSrc  MacInt
	MacDst  MacInt
	EthType EthernetType
	Vlan    uint16

	IHL        uint8  // ipv4 ihl or ipv6 fl4b
	TTL        uint8  // ipv4 ttl or ipv6 hop limit
	IpID       uint16 // (8B)
	IpSrc      uint32
	IpDst      uint32 // (8B)
	Ip6Src     net.IP // ipv6
	Ip6Dst     net.IP // ipv6
	Options    []byte
	IpFlags    uint16 // ipv4 Flags and Fragment Offset or ipv6 flow label
	Protocol   IPProtocol
	NextHeader IPProtocol // ipv6

	PortSrc uint16
	PortDst uint16              // (8B)
	TcpData MetaPacketTcpHeader // 绝大多数流量是TCP，不使用指针

	Direction       PacketDirection // flowgenerator负责初始化，表明MetaPacket方向
	IsActiveService bool            // flowgenerator负责初始化，表明服务端是否活跃
}

const (
	META_PACKET_SIZE_PER_BLOCK = 16
)

type MetaPacketBlock struct {
	Metas [META_PACKET_SIZE_PER_BLOCK]MetaPacket

	ActionFlags ActionFlag
	Count       uint8
	QueueIndex  uint8
	pool.ReferenceCount
}

func (p *MetaPacket) String() string {
	buffer := bytes.Buffer{}
	var format string
	format = "timestamp: %d tapType: %d tapPort: 0x%x vtapId: %d len: %d l2_end: %v, %v l3_end: %v, %v direction: %v\n"
	buffer.WriteString(fmt.Sprintf(format, p.Timestamp, p.TapType, p.TapPort, p.VtapId,
		p.PacketLen, p.L2End0, p.L2End1, p.L3End0, p.L3End1, p.Direction))
	if p.Tunnel != nil {
		buffer.WriteString(fmt.Sprintf("\ttunnel: %s\n", p.Tunnel))
	}
	format = "\t%s -> %s type: %04x vlan-id: %d\n"
	buffer.WriteString(fmt.Sprintf(format, Uint64ToMac(p.MacSrc), Uint64ToMac(p.MacDst), uint16(p.EthType), p.Vlan))
	if p.EthType == EthernetTypeIPv6 {
		format = "\t%v.%d -> %v.%d l3EpcId: %d -> %d proto: %v hop limit: %d flow lable: %d next header: %v options: %+x."
		buffer.WriteString(fmt.Sprintf(format, p.Ip6Src, p.PortSrc,
			p.Ip6Dst, p.PortDst, p.L3EpcId0, p.L3EpcId1, p.Protocol,
			p.TTL, uint32(p.IpFlags)|uint32(p.IHL)<<16, p.NextHeader, p.Options))
	} else {
		format = "\t%v:%d -> %v:%d l3EpcId: %d -> %d proto: %v ttl: %d ihl: %d id: %d flags: 0x%01x, fragment Offset: %d payload-len: %d"
		buffer.WriteString(fmt.Sprintf(format, IpFromUint32(p.IpSrc), p.PortSrc,
			IpFromUint32(p.IpDst), p.PortDst, p.L3EpcId0, p.L3EpcId1, p.Protocol,
			p.TTL, p.IHL, p.IpID, p.IpFlags>>13, p.IpFlags&0x1FFF, p.RawHeaderSize))
	}
	if p.Protocol == IPProtocolTCP {
		buffer.WriteString(fmt.Sprintf(" tcp: %v", &p.TcpData))
	}
	if p.EndpointData.Valid() {
		buffer.WriteString(fmt.Sprintf("\n\tEndpoint: %v", &p.EndpointData))
	}
	if p.PolicyData.Valid() {
		buffer.WriteString(fmt.Sprintf("\n\tPolicy: %v", &p.PolicyData))
	}

	if len(p.RawHeader) > 0 {
		endIndex := Min(len(p.RawHeader), 64)
		buffer.WriteString(fmt.Sprintf("\n\tRawHeader len: %v, RawHeader: %v", len(p.RawHeader), hex.EncodeToString(p.RawHeader[:endIndex])))
	}
	if len(p.RawIcmp) > 0 {
		endIndex := Min(len(p.RawIcmp), 64)
		buffer.WriteString(fmt.Sprintf("\n\tRawIcmp len: %v, RawIcmp: %v", len(p.RawIcmp), hex.EncodeToString(p.RawIcmp[:endIndex])))
	}

	return buffer.String()
}

func (h *MetaPacketTcpHeader) String() string {
	return fmt.Sprintf("&{Flags:%v Seq:%v Ack:%v DataOffset:%v WinSize:%v WinScale:%v SACKPermitted:%v MSS:%v Sack:%v}",
		h.Flags, h.Seq, h.Ack, h.DataOffset, h.WinSize, h.WinScale, h.SACKPermitted, h.MSS, h.Sack)
}

func (b *MetaPacketBlock) String() string {
	result := ""
	for i := uint8(0); i < b.Count; i++ {
		result += b.Metas[i].String() + "\n"
	}
	return result
}

var metaPacketBlockPool = pool.NewLockFreePool(func() interface{} {
	return new(MetaPacketBlock)
}, pool.OptionPoolSizePerCPU(16), pool.OptionInitFullPoolSize(16))

func AcquireMetaPacketBlock() *MetaPacketBlock {
	b := metaPacketBlockPool.Get().(*MetaPacketBlock)
	b.ReferenceCount.Reset()
	return b
}

func ReleaseMetaPacketBlock(x *MetaPacketBlock) {
	if x.SubReferenceCount() {
		return
	}

	*x = MetaPacketBlock{}
	metaPacketBlockPool.Put(x)
}
