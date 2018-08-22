package datatype

import (
	"fmt"
	"time"

	. "github.com/google/gopacket/layers"

	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const VLAN_ID_MASK = uint16((1 << 12) - 1)
const MIRRORED_TRAFFIC = 7

type RawPacket = []byte

type MetaPacketTcpHeader struct {
	Flags         uint8
	Seq           uint32
	Ack           uint32
	WinSize       uint16
	WinScale      uint8
	SACKPermitted bool
}

type MetaPacket struct {
	Timestamp      time.Duration
	InPort         uint32
	PacketLen      uint16
	Exporter       IPv4Int
	L2End0, L2End1 bool
	EndpointData   *EndpointData
	Raw            RawPacket

	Tunnel *TunnelInfo

	MacSrc, MacDst MacInt
	EthType        EthernetType
	Vlan           uint16

	IpSrc, IpDst IPv4Int
	Protocol     IPProtocol
	TTL          uint8

	PortSrc    uint16
	PortDst    uint16
	PayloadLen uint16
	TcpData    *MetaPacketTcpHeader
}

func (m *MetaPacket) String() string {
	return fmt.Sprintf("TIMESTAMP: %d INPORT: 0x%X EXPORTER: %v PKT_LEN: %d IS_L2_END: %v - %v ENDPOINTDATA: %p RAW: %p\n"+
		"    TUNNEL: %+v\n"+
		"    MAC: %s -> %s TYPE: %d VLAN: %d\n"+
		"    IP: %v -> %v PROTO: %d TTL: %d\n"+
		"    PORT: %d -> %d PAYLOAD_LEN: %d TCP: %+v",
		m.Timestamp, m.InPort, IpFromUint32(m.Exporter), m.PacketLen, m.L2End0, m.L2End1, m.EndpointData, m.Raw,
		m.Tunnel,
		Uint64ToMac(m.MacSrc), Uint64ToMac(m.MacDst), m.EthType, m.Vlan,
		IpFromUint32(m.IpSrc), IpFromUint32(m.IpDst), m.Protocol, m.TTL,
		m.PortSrc, m.PortDst, m.PayloadLen, m.TcpData)
}

func (h *MetaPacketTcpHeader) extractTcpOptions(stream *ByteStream) {
	for stream.Len() >= 2 { // 如果不足2B，那么只可能是NOP或END
		switch TCPOptionKind(stream.U8()) {
		case TCPOptionKindEndList:
			return
		case TCPOptionKindNop:
			continue
		case TCPOptionKindWindowScale:
			stream.U8() // skip length
			if stream.Len() > 0 {
				h.WinScale = stream.U8()
			}
		case TCPOptionKindSACKPermitted:
			stream.U8() // skip length
			h.SACKPermitted = true
		default: // others
			stream.U8() // skip length
		}
	}
}

func isVlanTagged(ethType EthernetType) bool {
	return ethType == EthernetTypeQinQ || ethType == EthernetTypeDot1Q
}

// TODO: 一个合法ip报文应当至少有30B的长度(不考虑非ip情形)
//       因此如果我们能够减少长度的判断，想必能够提升不少的性能
func (p *MetaPacket) Parse(packet RawPacket) bool {
	tunnel := TunnelInfo{}
	decapsulatedOffset := tunnel.Decapsulate(packet)
	if tunnel.Valid() {
		p.Tunnel = &tunnel
	}

	stream := ByteStream{packet[decapsulatedOffset:], 0}

	// L2
	if stream.Len() < ETH_HEADER_SIZE {
		return false
	}
	p.MacDst = MacIntFromBytes(stream.Field(MAC_ADDR_LEN))
	p.MacSrc = MacIntFromBytes(stream.Field(MAC_ADDR_LEN))
	p.EthType = EthernetType(stream.U16())
	if isVlanTagged(p.EthType) && stream.Len() > VLANTAG_LEN {
		vlanTag := stream.U16()
		vid := vlanTag & VLAN_ID_MASK
		if pcp := (vlanTag >> 12) & 0x3; pcp == MIRRORED_TRAFFIC {
			p.InPort = uint32((vid&0xF00)<<8) | uint32(vid&0xFF)
		}
		p.EthType = EthernetType(stream.U16())
	}
	if p.EthType == EthernetTypeDot1Q && stream.Len() > VLANTAG_LEN {
		p.Vlan = stream.U16() & VLAN_ID_MASK
		p.EthType = EthernetType(stream.U16())
	}

	// L3
	if p.EthType != EthernetTypeIPv4 || stream.Len() < MIN_IPV4_HEADER_SIZE {
		return true
	}
	ihl := (stream.U8() & 0xF)
	stream.Field(5) // skip till TTL
	fragmentOffset := stream.U16() & 0x1FFF
	p.TTL = stream.U8()
	p.Protocol = IPProtocol(stream.U8())
	stream.U16() // skip checksum
	p.IpSrc = stream.U32()
	p.IpDst = stream.U32()
	ipOptionsSize := int(ihl)*4 - MIN_IPV4_HEADER_SIZE
	if stream.Len() <= ipOptionsSize || fragmentOffset > 0 { // no more header
		return true
	}
	stream.Field(ipOptionsSize) // skip options

	// L4
	isValidUDP := p.Protocol == IPProtocolUDP && stream.Len() >= UDP_HEADER_SIZE
	isValidTCP := p.Protocol == IPProtocolTCP && stream.Len() >= MIN_TCP_HEADER_SIZE
	if !isValidUDP && !isValidTCP {
		return true
	}
	p.PortSrc = stream.U16()
	p.PortDst = stream.U16()
	if p.Protocol == IPProtocolUDP {
		p.PayloadLen = stream.U16() - UDP_HEADER_SIZE
		return true
	} // else TCP

	seq := stream.U32()
	ack := stream.U32()
	dataOffset := int(stream.U8() & 0xF0)
	flags := stream.U8()
	winSize := stream.U16()
	stream.Field(4) // skip checksum and URG Pointer
	optionsSize := dataOffset - MIN_TCP_HEADER_SIZE
	p.PayloadLen = uint16(stream.Len() - optionsSize)
	tcpHeader := &MetaPacketTcpHeader{flags, seq, ack, winSize, 0, false}
	tcpHeader.extractTcpOptions(&stream)
	p.TcpData = tcpHeader
	return true
}
