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

package adapter

import (
	"encoding/binary"
	"net"
	"time"

	. "github.com/google/gopacket/layers"

	. "github.com/deepflowio/deepflow/server/libs/datatype"
)

const (
	DELTA_TIMESTAMP_LEN  = 2
	UDP_BUFFER_SIZE      = 1 << 16
	ICMP_TYPE_CODE       = 2
	ICMP_ID_SEQ          = 4
	ICMP_REST            = 28
	IPV6_ADDR_LEN        = 16
	COMPRESS_HEADER_SIZE = 21 // VERSION(1) + SEQ(8) + TIMESAMP(8) + IF_MAC(4)
	_VERSION             = 8
)

const (
	ANALYZER_TRIDENT      = 0xffffff00 // 压缩报文来自analyzer上的trident
	ANALYZER_TRIDNET_MASK = 0xff       // 压缩报文来自analyzer上的trident时的掩码
)

type Decoded struct {
	// meta
	headerType HeaderType

	// l2
	mac0, mac1 MacInt
	vlan       uint16

	// l3
	ip0, ip1   uint32
	ihl        uint8
	ttl        uint8
	flags      uint8
	IpID       uint16
	fragOffset uint16
	l3EpcId0   uint16
	l3EpcId1   uint16

	// l3 ipv6
	ip6Src, ip6Dst net.IP

	// l4
	port0, port1 uint16
	dataOffset   uint8
}

type SequentialDecoder struct {
	timestamp time.Duration
	data      ByteStream
	seq       uint64
	pflags    PacketFlag
	forward   bool
	rx, tx    Decoded
	x         *Decoded

	tapPort                uint32
	tapType                TapType
	frameSize              uint16
	tridentDispatcherIndex uint8
}

func NewSequentialDecoder(data []byte) *SequentialDecoder {
	return &SequentialDecoder{data: NewByteStream(data)}
}

func (d *SequentialDecoder) initSequentialDecoder(data []byte) {
	d.data = NewByteStream(data)
}

func (d *SequentialDecoder) Seq() uint64 {
	return d.seq
}

func (d *SequentialDecoder) U8() uint8 {
	d.frameSize -= 1
	return d.data.U8()
}

func (d *SequentialDecoder) U16() uint16 {
	d.frameSize -= 2
	return d.data.U16()
}

func (d *SequentialDecoder) U32() uint32 {
	d.frameSize -= 4
	return d.data.U32()
}

func (d *SequentialDecoder) U64() uint64 {
	d.frameSize -= 8
	return d.data.U64()
}

func (d *SequentialDecoder) Field(len int) []byte {
	d.frameSize -= uint16(len)
	return d.data.Field(len)
}

func (d *SequentialDecoder) Skip(len int) {
	d.frameSize -= uint16(len)
	d.data.Skip(len)
}

func (d *SequentialDecoder) decodeTunnel() *TunnelInfo {
	src := d.U32()
	dst := d.U32()
	tunnelType := TunnelType(d.U8())
	id := uint32((d.U8()))<<16 | uint32(d.U16())
	return &TunnelInfo{Type: tunnelType, Src: src, Dst: dst, Id: id}
}

func (d *SequentialDecoder) decodeArp(meta *MetaPacket) {
	meta.RawHeader = make([]byte, ARP_HEADER_SIZE)
	copy(meta.RawHeader, d.data.Slice())

	d.Skip(8 + MAC_ADDR_LEN)
	meta.IpSrc = d.U32()
	d.Skip(MAC_ADDR_LEN)
	meta.IpDst = d.U32()
	meta.L3EpcId0 = d.U16()
	meta.L3EpcId1 = d.U16()
}

func (d *SequentialDecoder) decodeEthernet(meta *MetaPacket) {
	x := d.x
	if !d.pflags.IsSet(CFLAG_MAC0) {
		x.mac0 = MacIntFromBytes(d.Field(MAC_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_MAC1) {
		x.mac1 = MacIntFromBytes(d.Field(MAC_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_VLANTAG) {
		x.vlan = d.U16() & 0xFFF
	}

	meta.L2End0 = d.pflags.IsSet(PFLAG_SRC_ENDPOINT)
	meta.L2End1 = d.pflags.IsSet(PFLAG_DST_ENDPOINT)
	meta.L3End0 = d.pflags.IsSet(PFLAG_SRC_L3ENDPOINT)
	meta.L3End1 = d.pflags.IsSet(PFLAG_DST_L3ENDPOINT)
	meta.Vlan = x.vlan
	if d.forward {
		meta.MacSrc = x.mac0
		meta.MacDst = x.mac1
	} else {
		meta.MacSrc = x.mac1
		meta.MacDst = x.mac0
	}
	if x.headerType == HEADER_TYPE_ARP {
		meta.EthType = EthernetTypeARP
		d.decodeArp(meta)
	} else if x.headerType < HEADER_TYPE_IPV4 {
		meta.EthType = EthernetType(d.U16())
	} else if x.headerType.IsIpv6() {
		meta.EthType = EthernetTypeIPv6
		d.decodeIPv6(meta)
	} else {
		meta.EthType = EthernetTypeIPv4
		d.decodeIPv4(meta)
	}
}

func (d *SequentialDecoder) decodeIPv6(meta *MetaPacket) {
	x := d.x
	if !d.pflags.IsSet(CFLAG_DATAOFF_IHL) {
		b := d.U8()
		x.dataOffset = b >> 4 // XXX: Valid in TCP Only
		x.ihl = b & 0xf
	}
	meta.IHL = x.ihl
	if !d.pflags.IsSet(CFLAG_FLAGS_FRAG_OFFSET) {
		x.fragOffset = d.U16()
	}
	meta.IpFlags = x.fragOffset
	if !d.pflags.IsSet(CFLAG_TTL) {
		x.ttl = d.U8()
	}
	meta.TTL = x.ttl
	if !d.pflags.IsSet(CFLAG_IP0) {
		x.ip6Src = net.IP(d.Field(IPV6_ADDR_LEN))
		x.l3EpcId0 = d.U16()
	}
	if !d.pflags.IsSet(CFLAG_IP1) {
		x.ip6Dst = net.IP(d.Field(IPV6_ADDR_LEN))
		x.l3EpcId1 = d.U16()
	}
	meta.Ip6Src = make(net.IP, 16)
	meta.Ip6Dst = make(net.IP, 16)
	if d.forward {
		copy(meta.Ip6Src, x.ip6Src)
		copy(meta.Ip6Dst, x.ip6Dst)
		meta.L3EpcId0, meta.L3EpcId1 = x.l3EpcId0, x.l3EpcId1
	} else {
		copy(meta.Ip6Src, x.ip6Dst)
		copy(meta.Ip6Dst, x.ip6Src)
		meta.L3EpcId0, meta.L3EpcId1 = x.l3EpcId1, x.l3EpcId0
	}
	meta.NextHeader = IPProtocol(d.U8())
	if length := d.U8(); length > 0 {
		meta.Options = d.Field(int(length))
	}
	if x.headerType == HEADER_TYPE_IPV6 {
		meta.Protocol = meta.NextHeader
		d.decodePacket(meta)
		return
	}
	d.decodeL4(meta)
}

func (d *SequentialDecoder) decodeIPv4(meta *MetaPacket) {
	x := d.x
	if !d.pflags.IsSet(CFLAG_DATAOFF_IHL) {
		b := d.U8()
		x.ihl = b & 0xF
		x.dataOffset = b >> 4 // XXX: Valid in TCP Only
	}
	meta.IHL = x.ihl
	x.IpID = d.U16()
	meta.IpID = x.IpID

	if !d.pflags.IsSet(CFLAG_FLAGS_FRAG_OFFSET) {
		value := d.U16()
		x.flags, x.fragOffset = uint8(value>>13), value&0x1FFF
	}
	meta.IpFlags = uint16(x.flags<<13) | x.fragOffset

	if !d.pflags.IsSet(CFLAG_TTL) {
		x.ttl = d.U8()
	}
	meta.TTL = x.ttl

	if !d.pflags.IsSet(CFLAG_IP0) {
		x.ip0 = binary.BigEndian.Uint32(d.Field(IP_ADDR_LEN))
		x.l3EpcId0 = d.U16()
	}
	if !d.pflags.IsSet(CFLAG_IP1) {
		x.ip1 = binary.BigEndian.Uint32(d.Field(IP_ADDR_LEN))
		x.l3EpcId1 = d.U16()
	}
	if d.forward {
		meta.IpSrc = x.ip0
		meta.IpDst = x.ip1
		meta.L3EpcId0, meta.L3EpcId1 = x.l3EpcId0, x.l3EpcId1
	} else {
		meta.IpSrc = x.ip1
		meta.IpDst = x.ip0
		meta.L3EpcId0, meta.L3EpcId1 = x.l3EpcId1, x.l3EpcId0
	}
	if x.headerType == HEADER_TYPE_IPV4_ICMP {
		meta.Protocol = IPProtocolICMPv4
		d.decodeICMP(meta)
		return
	} else if x.headerType == HEADER_TYPE_IPV4 {
		proto := d.U8()
		meta.Protocol = IPProtocol(proto)
		d.decodePacket(meta)
		return
	}
	d.decodeL4(meta)
}

func (d *SequentialDecoder) decodeICMP(meta *MetaPacket) {
	stream := &d.data
	meta.RawIcmp = make([]byte, ICMP_HEADER_SIZE+ICMP_REST)
	icmpType, icmpCode := d.U8(), d.U8()
	meta.RawIcmp[0] = icmpType
	meta.RawIcmp[1] = icmpCode
	dataLen := 0
	switch icmpType {
	case ICMPv4TypeDestinationUnreachable:
		fallthrough
	case ICMPv4TypeSourceQuench:
		fallthrough
	case ICMPv4TypeRedirect:
		fallthrough
	case ICMPv4TypeTimeExceeded:
		fallthrough
	case ICMPv4TypeParameterProblem:
		dataLen = ICMP_ID_SEQ + ICMP_REST
		if stream.Len() < dataLen {
			dataLen = stream.Len()
		}
		meta.RawIcmp = append(meta.RawIcmp[:4], d.Field(dataLen)...)
		dataLen += 4
	default:
		dataLen = 4 + ICMP_ID_SEQ
		meta.RawIcmp = append(meta.RawIcmp[:4], d.Field(ICMP_ID_SEQ)...)
	}
	d.decodePacket(meta)
}

func (d *SequentialDecoder) decodeL4(meta *MetaPacket) {
	x := d.x
	if !d.pflags.IsSet(CFLAG_PORT0) {
		x.port0 = d.U16()
	}
	if !d.pflags.IsSet(CFLAG_PORT1) {
		x.port1 = d.U16()
	}

	if d.forward {
		meta.PortSrc = x.port0
		meta.PortDst = x.port1
	} else {
		meta.PortSrc = x.port1
		meta.PortDst = x.port0
	}
	if x.headerType == HEADER_TYPE_IPV4_UDP || x.headerType == HEADER_TYPE_IPV6_UDP {
		meta.Protocol = IPProtocolUDP
		d.decodePacket(meta)
		return
	}
	meta.Protocol = IPProtocolTCP
	tcpData := &meta.TcpData
	tcpData.Seq = d.U32()
	tcpData.Ack = d.U32()
	tcpData.Flags = d.U8()
	tcpData.WinSize = d.U16()
	tcpData.DataOffset = x.dataOffset
	if x.dataOffset > 5 {
		optionFlag := d.U8()
		if optionFlag&TCP_OPT_FLAG_WIN_SCALE > 0 {
			tcpData.WinScale = d.U8()
		}
		if optionFlag&TCP_OPT_FLAG_MSS > 0 {
			tcpData.MSS = d.U16()
		}
		sackPermit := optionFlag&TCP_OPT_FLAG_SACK_PERMIT > 0
		if sackPermit {
			tcpData.SACKPermitted = true
		}
		sackLength := int(optionFlag & TCP_OPT_FLAG_SACK)
		if sackLength > 0 {
			tcpData.Sack = make([]byte, sackLength)
			copy(tcpData.Sack, d.Field(sackLength))
		}
	}

	d.decodePacket(meta)
}

func (d *SequentialDecoder) DecodeHeader(frameSize uint16) (bool, uint16) {
	if frameSize <= COMPRESS_HEADER_SIZE {
		return true, 0
	}
	d.frameSize = frameSize
	version := d.U8() // U8 reserved and U8 version
	if version != _VERSION {
		return true, 0
	}
	vtapId := d.U16()
	d.seq = d.U64()
	indexAndTimestamp := d.U64()
	index := uint8(indexAndTimestamp >> 56)
	if index >= 16 { // Trident最大16个队列[0, 15]
		return true, 0
	}
	d.timestamp = time.Duration(indexAndTimestamp&0xffffffffffffff) * time.Microsecond
	inPort := d.U32()
	if inPort&ANALYZER_TRIDENT == ANALYZER_TRIDENT {
		d.tapType = TapType(inPort & ANALYZER_TRIDNET_MASK)
	} else {
		d.tapType = TAP_CLOUD
		d.tapPort = inPort
	}
	d.tridentDispatcherIndex = index
	return false, vtapId
}

func (d *SequentialDecoder) NextPacket(meta *MetaPacket) bool {
	if d.frameSize == 0 {
		return true
	}
	delta := d.U16()
	totalSize := d.U16()
	d.pflags = PacketFlag(d.U16())
	if d.pflags.IsSet(PFLAG_DST_ENDPOINT) {
		d.x = &d.rx
		d.forward = false
	} else {
		d.x = &d.tx
		d.forward = true
	}
	if !d.pflags.IsSet(CFLAG_HEADER_TYPE) {
		d.x.headerType = HeaderType(d.U8())
	}
	d.timestamp += time.Duration(delta) * time.Microsecond // µs to ns
	if d.pflags.IsSet(PFLAG_TUNNEL) {
		meta.Tunnel = d.decodeTunnel()
	}
	meta.PacketLen = totalSize
	meta.Timestamp = d.timestamp
	d.decodeEthernet(meta)
	return false
}

func (d *SequentialDecoder) decodePacket(meta *MetaPacket) {
	meta.RawHeaderSize = d.U16()
	if meta.RawHeaderSize > 0 {
		meta.RawHeader = make([]byte, meta.RawHeaderSize)
		copy(meta.RawHeader, d.Field(int(meta.RawHeaderSize)))
	}
}
