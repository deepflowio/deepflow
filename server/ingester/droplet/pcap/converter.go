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

package pcap

import (
	"encoding/binary"

	"github.com/google/gopacket/layers"

	"github.com/deepflowio/deepflow/server/libs/datatype"
)

const (
	SLICE_PAYLOAD_LEN = 2
	MAX_HEADER_LEN    = 128
	MAC_ADDRESS_LEN   = 6
	IP_ADDRESS_LEN    = 4
)

type RawPacket []byte

func NewRawPacket(buffer []byte) RawPacket {
	return buffer
}

func (p RawPacket) MetaPacketToRaw(packet *datatype.MetaPacket, tcpipChecksum bool) int {
	if packet.RawHeaderSize > 0 {
		copy(p, packet.RawHeader)
		return int(packet.RawHeaderSize)
	}

	size := 0

	size += p.fillEthernet(packet, size)
	l3Offset := size

	switch packet.EthType {
	case layers.EthernetTypeIPv4:
		size += p.fillIPv4(packet, size)
	case layers.EthernetTypeARP:
		size += p.fillARP(packet, size)
	case layers.EthernetTypeIPv6:
		size += p.fillIPv6(packet, size)
	}

	if packet.EthType == layers.EthernetTypeIPv4 || packet.EthType == layers.EthernetTypeIPv6 {
		switch packet.Protocol {
		case layers.IPProtocolICMPv4:
			size += p.fillICMPv4(packet, size)
		case layers.IPProtocolTCP:
			size += p.fillTCP(packet, size, l3Offset, tcpipChecksum)
		case layers.IPProtocolUDP:
			size += p.fillUDP(packet, size, l3Offset, tcpipChecksum)
		default:
			size += p.fillOthers(packet, size)
		}
	}
	p.fillIpTotalLen(packet, l3Offset+IPV4_TOTAL_LENGTH_OFFSET)
	return size
}

const (
	ETHERNET_LEN = 14
	VLAN_LEN     = 4
)

// only when packet's length <= 64B, need adjust ip total length
func (p RawPacket) fillIpTotalLen(packet *datatype.MetaPacket, at int) {
	if packet.PacketLen > 64 || packet.EthType != layers.EthernetTypeIPv4 {
		return
	}

	ipTotalLen := uint16(packet.IHL << 2)

	switch packet.Protocol {
	case layers.IPProtocolICMPv4:
		if packet.RawHeader == nil {
			return
		}
		ipTotalLen += uint16(len(packet.RawHeader))
	case layers.IPProtocolTCP:
		if packet.TcpData.DataOffset == 0 {
			return
		}
		ipTotalLen += uint16(packet.TcpData.DataOffset << 2)
	case layers.IPProtocolUDP:
		ipTotalLen += 8
	}

	binary.BigEndian.PutUint16(p[at:], ipTotalLen)
}

func (p RawPacket) fillEthernet(packet *datatype.MetaPacket, start int) int {
	base := p[start:]
	offset := 0

	macIntToBytes(packet.MacDst, base[offset:])
	offset += MAC_ADDRESS_LEN
	macIntToBytes(packet.MacSrc, base[offset:])
	offset += MAC_ADDRESS_LEN

	if packet.Vlan != 0 {
		binary.BigEndian.PutUint16(base[offset:], uint16(layers.EthernetTypeDot1Q))
		offset += 2
		binary.BigEndian.PutUint16(base[offset:], uint16(packet.Vlan))
		offset += 2
	}

	binary.BigEndian.PutUint16(base[offset:], uint16(packet.EthType))
	return offset + 2
}

const (
	IPV4_VERSION_IHL_OFFSET     = 0
	IPV4_DSCP_ECN_OFFSET        = 1
	IPV4_TOTAL_LENGTH_OFFSET    = 2
	IPV4_ID_OFFSET              = 4
	IPV4_FLAGS_FRAGMENT_OFFSET  = 6
	IPV4_TTL_OFFSET             = 8
	IPV4_PROTOCOL_OFFSET        = 9
	IPV4_HEADER_CHECKSUM_OFFSET = 10
	IPV4_SIP_OFFSET             = 12
	IPV4_DIP_OFFSET             = 16
	IPV4_LEN                    = 20 // no options
)

const (
	IPV4_VERSION = 4
	IPV6_VERSION = 6
)

func (p RawPacket) fillIPv4(packet *datatype.MetaPacket, start int) int {
	base := p[start:]

	base[IPV4_VERSION_IHL_OFFSET] = (IPV4_VERSION << 4) | packet.IHL
	base[IPV4_DSCP_ECN_OFFSET] = 0
	binary.BigEndian.PutUint16(base[IPV4_TOTAL_LENGTH_OFFSET:], packet.PacketLen-uint16(start))
	binary.BigEndian.PutUint16(base[IPV4_ID_OFFSET:], packet.IpID)
	binary.BigEndian.PutUint16(base[IPV4_FLAGS_FRAGMENT_OFFSET:], packet.IpFlags)
	base[IPV4_TTL_OFFSET] = packet.TTL
	base[IPV4_PROTOCOL_OFFSET] = byte(packet.Protocol)
	binary.BigEndian.PutUint32(base[IPV4_SIP_OFFSET:], packet.IpSrc)
	binary.BigEndian.PutUint32(base[IPV4_DIP_OFFSET:], packet.IpDst)

	base[IPV4_HEADER_CHECKSUM_OFFSET] = 0
	base[IPV4_HEADER_CHECKSUM_OFFSET+1] = 0
	var csum uint32
	for i := 0; i < IPV4_LEN; i += 2 {
		csum += uint32(base[i]) << 8
		csum += uint32(base[i+1])
	}
	for csum > 0xFFFF {
		csum = (csum >> 16) + (csum & 0xFFFF)
	}
	binary.BigEndian.PutUint16(base[IPV4_HEADER_CHECKSUM_OFFSET:], ^uint16(csum))

	return IPV4_LEN
}

func (p RawPacket) fillARP(packet *datatype.MetaPacket, start int) int {
	return copy(p[start:], packet.RawHeader)
}

const (
	IPV6_VERSION_FLOW_LABEL_OFFSET = 0
	IPV6_PAYLOAD_LENGTH_OFFSET     = 4
	IPV6_NEXT_HEADER_OFFSET        = 6
	IPV6_HOP_LIMIT_OFFSET          = 7
	IPV6_SRC_ADDRESS_OFFSET        = 8
	IPV6_DST_ADDRESS_OFFSET        = 24
	IPV6_OPTIONS_OFFSET            = 40
	IPV6_HEADER_LEN                = 40
)

func (p RawPacket) getIPv6Payload(packet *datatype.MetaPacket) uint16 {
	payload := packet.PacketLen - ETHERNET_LEN - IPV6_HEADER_LEN
	if packet.Vlan > 0 {
		payload -= VLAN_LEN
	}
	return payload
}

func (p RawPacket) fillIPv6(packet *datatype.MetaPacket, start int) int {
	base := p[start:]
	versionAndFlowLabel := uint32(IPV6_VERSION)<<28 | uint32(packet.IHL)<<16 | uint32(packet.IpFlags)
	payload := p.getIPv6Payload(packet)

	binary.BigEndian.PutUint32(base[IPV6_VERSION_FLOW_LABEL_OFFSET:], versionAndFlowLabel)
	binary.BigEndian.PutUint16(base[IPV6_PAYLOAD_LENGTH_OFFSET:], payload)
	base[IPV6_NEXT_HEADER_OFFSET] = byte(packet.NextHeader)
	base[IPV6_HOP_LIMIT_OFFSET] = packet.TTL
	copy(base[IPV6_SRC_ADDRESS_OFFSET:], packet.Ip6Src)
	copy(base[IPV6_DST_ADDRESS_OFFSET:], packet.Ip6Dst)
	optionsLength := len(packet.Options)
	if optionsLength > 0 {
		copy(base[IPV6_OPTIONS_OFFSET:], packet.Options)
	}
	return IPV6_HEADER_LEN + optionsLength
}

func (p RawPacket) fillICMPv4(packet *datatype.MetaPacket, start int) int {
	return copy(p[start:], packet.RawIcmp)
}

const (
	TCP_SPORT_OFFSET       = 0
	TCP_DPORT_OFFSET       = 2
	TCP_SEQ_NUMBER_OFFSET  = 4
	TCP_ACK_NUMBER_OFFSET  = 8
	TCP_DATA_OFFSET_OFFSET = 12
	TCP_FLAGS_OFFSET       = 13 // NS not included
	TCP_WINDOW_SIZE_OFFSET = 14
	TCP_CHECKSUM_OFFSET    = 16
	TCP_URG_PTR_OFFSET     = 18
	TCP_OPTIONS_OFFSET     = 20
	TCP_MAX_OPTIONS_LEN    = 40
	TCP_MIN_LEN            = 20
)

const (
	TCP_OPTION_KIND_MSS_LEN            = 4
	TCP_OPTION_KIND_WINDOW_SCALE_LEN   = 3
	TCP_OPTION_KIND_SACK_PERMITTED_LEN = 2
)

func (p RawPacket) fillTCP(packet *datatype.MetaPacket, start, ipv4Offset int, checksum bool) int {
	if packet.TcpData.DataOffset == 0 {
		return 0
	}

	base := p[start:]

	binary.BigEndian.PutUint16(base[TCP_SPORT_OFFSET:], packet.PortSrc)
	binary.BigEndian.PutUint16(base[TCP_DPORT_OFFSET:], packet.PortDst)

	binary.BigEndian.PutUint32(base[TCP_SEQ_NUMBER_OFFSET:], packet.TcpData.Seq)
	binary.BigEndian.PutUint32(base[TCP_ACK_NUMBER_OFFSET:], packet.TcpData.Ack)
	base[TCP_DATA_OFFSET_OFFSET] = packet.TcpData.DataOffset << 4
	base[TCP_FLAGS_OFFSET] = packet.TcpData.Flags
	binary.BigEndian.PutUint16(base[TCP_WINDOW_SIZE_OFFSET:], packet.TcpData.WinSize)
	binary.BigEndian.PutUint16(base[TCP_URG_PTR_OFFSET:], 0)

	optOffset := 0
	if packet.TcpData.MSS > 0 {
		base[TCP_OPTIONS_OFFSET+optOffset] = byte(layers.TCPOptionKindMSS)
		base[TCP_OPTIONS_OFFSET+optOffset+1] = TCP_OPTION_KIND_MSS_LEN
		binary.BigEndian.PutUint16(base[TCP_OPTIONS_OFFSET+optOffset+2:], packet.TcpData.MSS)
		optOffset += TCP_OPTION_KIND_MSS_LEN
	}
	if packet.TcpData.WinScale > 0 {
		base[TCP_OPTIONS_OFFSET+optOffset] = byte(layers.TCPOptionKindWindowScale)
		base[TCP_OPTIONS_OFFSET+optOffset+1] = TCP_OPTION_KIND_WINDOW_SCALE_LEN
		base[TCP_OPTIONS_OFFSET+optOffset+2] = packet.TcpData.WinScale
		optOffset += TCP_OPTION_KIND_WINDOW_SCALE_LEN
	}
	if packet.TcpData.SACKPermitted {
		base[TCP_OPTIONS_OFFSET+optOffset] = byte(layers.TCPOptionKindSACKPermitted)
		base[TCP_OPTIONS_OFFSET+optOffset+1] = TCP_OPTION_KIND_SACK_PERMITTED_LEN
		optOffset += TCP_OPTION_KIND_SACK_PERMITTED_LEN
	}
	if sackLen := len(packet.TcpData.Sack); sackLen > 0 {
		if sackLen&0x7 != 0 || sackLen > 32 { // not multiple of 8
			log.Debugf("SAck length %d incorrect", sackLen)
		} else {
			base[TCP_OPTIONS_OFFSET+optOffset] = byte(layers.TCPOptionKindSACK)
			base[TCP_OPTIONS_OFFSET+optOffset+1] = byte(sackLen + 2)
			copy(base[TCP_OPTIONS_OFFSET+optOffset+2:], packet.TcpData.Sack)
			optOffset += sackLen + 2
		}
	}
	length := int(packet.TcpData.DataOffset) << 2

	if checksum {
		binary.BigEndian.PutUint16(base[TCP_CHECKSUM_OFFSET:], p.tcpIPChecksum(layers.IPProtocolTCP, ipv4Offset, start, length))
	} else {
		binary.BigEndian.PutUint16(base[TCP_CHECKSUM_OFFSET:], 0)
	}

	return length
}

const (
	UDP_SPORT_OFFSET    = 0
	UDP_DPORT_OFFSET    = 2
	UDP_LENGTH_OFFSET   = 4
	UDP_CHECKSUM_OFFSET = 6
	UDP_LEN             = 8
)

func (p RawPacket) fillUDP(packet *datatype.MetaPacket, start, ipv4Offset int, checksum bool) int {
	base := p[start:]

	length := UDP_LEN
	binary.BigEndian.PutUint16(base[UDP_SPORT_OFFSET:], packet.PortSrc)
	binary.BigEndian.PutUint16(base[UDP_DPORT_OFFSET:], packet.PortDst)
	binary.BigEndian.PutUint16(base[UDP_LENGTH_OFFSET:], uint16(length))
	if checksum {
		binary.BigEndian.PutUint16(base[UDP_CHECKSUM_OFFSET:], p.tcpIPChecksum(layers.IPProtocolUDP, ipv4Offset, start, UDP_LEN))
	} else {
		binary.BigEndian.PutUint16(base[UDP_CHECKSUM_OFFSET:], 0)
	}

	return length
}

func (p RawPacket) tcpIPChecksum(protocol layers.IPProtocol, ipv4Offset, tcpIPOffset int, length int) uint16 {
	csum := uint32(0)

	// pseudo header
	ipv4Layer := p[ipv4Offset:]
	csum += (uint32(ipv4Layer[IPV4_SIP_OFFSET]) + uint32(ipv4Layer[IPV4_SIP_OFFSET+2])) << 8
	csum += uint32(ipv4Layer[IPV4_SIP_OFFSET+1]) + uint32(ipv4Layer[IPV4_SIP_OFFSET+3])
	csum += (uint32(ipv4Layer[IPV4_DIP_OFFSET]) + uint32(ipv4Layer[IPV4_DIP_OFFSET+2])) << 8
	csum += uint32(ipv4Layer[IPV4_DIP_OFFSET+1]) + uint32(ipv4Layer[IPV4_DIP_OFFSET+3])
	csum += uint32(protocol) + uint32(length)
	// tcp/ip header
	tcpIPLayer := p[tcpIPOffset:]
	for i := 0; i < length; i += 2 {
		csum += uint32(binary.BigEndian.Uint16(tcpIPLayer[i : i+2]))
	}
	for csum > 0xFFFF {
		csum = (csum >> 16) + (csum & 0xFFFF)
	}

	return ^uint16(csum)
}

func min(x, y int) int {
	if x > y {
		return y
	}
	return x
}

func macIntToBytes(macInt datatype.MacInt, mac []byte) {
	binary.BigEndian.PutUint16(mac, uint16(macInt>>32))
	binary.BigEndian.PutUint32(mac[2:], uint32(macInt))
}

func (p RawPacket) fillOthers(packet *datatype.MetaPacket, start int) int {
	base := p[start:]

	length := 0
	if packet.RawHeaderSize > 0 {
		length += copy(base, packet.RawHeader)
	}
	return length
}
