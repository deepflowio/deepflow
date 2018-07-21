package handler

import (
	. "encoding/binary"

	. "github.com/google/gopacket/layers"

	. "gitlab.x.lan/yunshan/droplet/utils"
)

type MetaPacket struct {
	timestamp int64 // unit Microsecond

	TunnelInfo

	headerType  HeaderType
	pktSize     int
	vlanTagSize int
	l2L3OptSize int // 802.1Q + IPv4 Optional Fields
	l4OptSize   int // ICMP Payload / TCP Optional Fields

	srcEndpoint, dstEndpoint bool

	offsetMac0, offsetMac1   int
	offsetIp0, offsetIp1     int
	offsetPort0, offsetPort1 int

	dataOffsetIhl uint8

	tcpOptionsFlag       uint8
	tcpOptWinScaleOffset int
	tcpOptMssOffset      int
	tcpOptSackOffset     int
}

var emptyMetaPacket = MetaPacket{
	offsetMac0:           FIELD_SA_OFFSET,
	offsetMac1:           FIELD_DA_OFFSET,
	offsetIp0:            FIELD_SIP_OFFSET,
	offsetIp1:            FIELD_DIP_OFFSET,
	offsetPort0:          FIELD_SPORT_OFFSET,
	offsetPort1:          FIELD_DPORT_OFFSET,
	tcpOptWinScaleOffset: -1,
	tcpOptMssOffset:      -1,
	tcpOptSackOffset:     -1,
}

func NewMetaPacket() *MetaPacket {
	m := emptyMetaPacket
	return &m
}

func (m *MetaPacket) Reset() *MetaPacket {
	*m = emptyMetaPacket
	return m
}

func (m *MetaPacket) TcpOptionsSize() int {
	if m.headerType != HEADER_TYPE_IPV4_TCP || m.l4OptSize == 0 {
		return 0
	}
	size := 1
	if m.tcpOptionsFlag&TCP_OPT_FLAG_MSS > 0 {
		size += TCP_OPT_MSS_LEN - 2
	}
	if m.tcpOptionsFlag&TCP_OPT_FLAG_WIN_SCALE > 0 {
		size += TCP_OPT_WIN_SCALE_LEN - 2
	}
	return size + int(m.tcpOptionsFlag&TCP_OPT_FLAG_SACK)
}

func field(data []byte, offset int, len int) []byte { // inline
	return data[offset : offset+len]
}

func (m *MetaPacket) updateTcpOpt(packet []byte) {
	offset := MIN_PACKET_SIZES[m.headerType] + m.l2L3OptSize
	payloadOffset := offset + m.l4OptSize

	for offset+1 < payloadOffset { // 如果不足2B，EOL和NOP都可以忽略
		assumeLength := Max(int(packet[offset+1]), 2)
		switch packet[offset] {
		case TCPOptionKindEndList:
			return
		case TCPOptionKindNop:
			offset++
		case TCPOptionKindMSS:
			if offset+TCP_OPT_MSS_LEN > payloadOffset {
				return
			}
			m.tcpOptMssOffset = offset + 2
			m.tcpOptionsFlag |= TCP_OPT_FLAG_MSS
			offset += TCP_OPT_MSS_LEN
		case TCPOptionKindWindowScale:
			if offset+TCP_OPT_WIN_SCALE_LEN > payloadOffset {
				return
			}
			m.tcpOptWinScaleOffset = offset + 2
			m.tcpOptionsFlag |= TCP_OPT_FLAG_WIN_SCALE
			offset += TCP_OPT_WIN_SCALE_LEN
		case TCPOptionKindSACKPermitted:
			m.tcpOptionsFlag |= TCP_OPT_FLAG_SACK_PERMIT
			offset += 2
		case TCPOptionKindSACK:
			if offset+assumeLength > payloadOffset {
				return
			}
			sackSize := assumeLength - 2
			if sackSize > 32 {
				return
			}
			m.tcpOptSackOffset = offset + 2
			m.tcpOptionsFlag |= uint8(sackSize)
			offset += assumeLength
		default: // others
			offset += assumeLength
		}
	}
}

func (m *MetaPacket) SetTunnelInfo(tunnelInfo *TunnelInfo) *MetaPacket {
	m.TunnelInfo = *tunnelInfo
	return m
}

func (m *MetaPacket) Update(packet []byte, srcEndpoint, dstEndpoint bool, timestamp int64) bool {
	m.timestamp = timestamp
	m.srcEndpoint, m.dstEndpoint = srcEndpoint, dstEndpoint
	m.pktSize = len(packet)
	sizeChecker := len(packet)

	// ETH
	sizeChecker -= MIN_HEADER_SIZES[HEADER_TYPE_ETH]
	if sizeChecker < 0 {
		return false
	}
	vlanTagSize := 0
	ethType := EthernetType(BigEndian.Uint16(packet[FIELD_ETH_TYPE_OFFSET:]))
	if ethType == EthernetTypeDot1Q {
		vlanTagSize = 4
		sizeChecker -= vlanTagSize
		if sizeChecker < 0 {
			return false
		}
		ethType = EthernetType(BigEndian.Uint16(packet[FIELD_ETH_TYPE_OFFSET+vlanTagSize:]))
	}

	m.headerType = HEADER_TYPE_ETH
	m.vlanTagSize = vlanTagSize
	if dstEndpoint { // Inbound
		m.offsetMac0, m.offsetMac1 = m.offsetMac1, m.offsetMac0
	}

	switch ethType {
	case EthernetTypeARP:
		sizeChecker -= MIN_HEADER_SIZES[HEADER_TYPE_ARP]
		if sizeChecker < 0 {
			return true
		}
		m.headerType = HEADER_TYPE_ARP
		return true
	case EthernetTypeIPv4:
		sizeChecker -= MIN_HEADER_SIZES[HEADER_TYPE_IPV4]
		if sizeChecker < 0 {
			return true
		}
		break
	default:
		return true
	}

	// IPv4
	m.headerType = HEADER_TYPE_IPV4
	ihl := int(packet[FIELD_IHL_OFFSET+vlanTagSize] & 0xF)
	m.dataOffsetIhl = uint8(ihl)

	m.offsetIp0 += vlanTagSize
	m.offsetIp1 += vlanTagSize
	if m.dstEndpoint {
		m.offsetIp0, m.offsetIp1 = m.offsetIp1, m.offsetIp0
	}

	totalLength := int(BigEndian.Uint16(packet[FIELD_TOTAL_LEN_OFFSET+vlanTagSize:]))
	m.pktSize = totalLength + MIN_PACKET_SIZES[HEADER_TYPE_ETH] + vlanTagSize

	l3OptSize := int(ihl)*4 - 20
	sizeChecker -= l3OptSize
	if sizeChecker < 0 {
		return true
	}
	m.l2L3OptSize = vlanTagSize + l3OptSize

	if BigEndian.Uint16(packet[FIELD_FRAG_OFFSET+vlanTagSize:])&0xFFF > 0 { // fragment
		m.headerType = HEADER_TYPE_IPV4
		return true
	}

	ipProtocol := IPProtocol(packet[FIELD_PROTO_OFFSET+vlanTagSize])
	switch ipProtocol {
	case IPProtocolICMPv4:
		sizeChecker -= MIN_HEADER_SIZES[HEADER_TYPE_IPV4_ICMP]
		if sizeChecker < 0 {
			return true
		}
		switch packet[FIELD_ICMP_TYPE_CODE_OFFSET+m.l2L3OptSize] {
		case ICMPv4TypeDestinationUnreachable:
			fallthrough
		case ICMPv4TypeSourceQuench:
			fallthrough
		case ICMPv4TypeRedirect:
			fallthrough
		case ICMPv4TypeTimeExceeded:
			fallthrough
		case ICMPv4TypeParameterProblem:
			m.l4OptSize = FIELD_ICMP_REST_LEN
			sizeChecker -= m.l4OptSize
			if sizeChecker < 0 {
				m.l4OptSize = 0
				return true
			}
		}
		m.headerType = HEADER_TYPE_IPV4_ICMP
		return true
	case IPProtocolUDP:
		sizeChecker -= MIN_HEADER_SIZES[HEADER_TYPE_IPV4_UDP]
		if sizeChecker < 0 {
			return true
		}
		m.headerType = HEADER_TYPE_IPV4_UDP
	case IPProtocolTCP:
		sizeChecker -= MIN_HEADER_SIZES[HEADER_TYPE_IPV4_TCP]
		if sizeChecker < 0 {
			return true
		}
		dataOffset := packet[FIELD_TCP_DATAOFF_OFFSET+m.l2L3OptSize] >> 4
		m.dataOffsetIhl |= dataOffset << 4
		m.l4OptSize = int(dataOffset*4) - 20
		sizeChecker -= m.l4OptSize
		if sizeChecker < 0 {
			return true
		}
		m.headerType = HEADER_TYPE_IPV4_TCP
		if dataOffset > 5 {
			m.updateTcpOpt(packet)
		}
	default:
		return true
	}

	if m.headerType == HEADER_TYPE_IPV4_UDP || m.headerType == HEADER_TYPE_IPV4_TCP {
		m.offsetPort0 += m.l2L3OptSize
		m.offsetPort1 += m.l2L3OptSize
		if m.dstEndpoint {
			m.offsetPort0, m.offsetPort1 = m.offsetPort1, m.offsetPort0
		}
	}
	return true
}
