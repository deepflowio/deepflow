package datatype

import (
	"bytes"
	"encoding/hex"
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
	DataOffset    uint8
	WinSize       uint16
	WinScale      uint8
	SACKPermitted bool
	MSS           uint16
	Sack          []byte // sack value
}

type MetaPacket struct {
	ReferenceCount

	Timestamp      time.Duration
	InPort         uint32
	PacketLen      uint16
	Exporter       IPv4Int
	L2End0, L2End1 bool
	EndpointData   *EndpointData
	PolicyData     *PolicyData
	Raw            RawPacket
	Invalid        bool
	Hash           uint32

	Tunnel *TunnelInfo

	MacSrc, MacDst MacInt
	EthType        EthernetType
	Vlan           uint16

	IpSrc, IpDst IPv4Int
	Protocol     IPProtocol
	TTL          uint8
	IHL          uint8
	IpID         uint16
	IpFlags      uint16 // Flags and Fragment Offset

	PortSrc    uint16
	PortDst    uint16
	PayloadLen uint16
	TcpData    *MetaPacketTcpHeader

	RawHeader []byte // total arp, or icmp header
}

func (p *MetaPacket) GenerateHash() uint32 {
	portSrc := uint32(p.PortSrc)
	portDst := uint32(p.PortDst)
	if portSrc >= portDst {
		p.Hash = p.InPort ^ p.IpSrc ^ p.IpDst ^ ((portSrc << 16) | portDst)
	} else {
		p.Hash = p.InPort ^ p.IpSrc ^ p.IpDst ^ ((portDst << 16) | portSrc)
	}
	return p.Hash
}

func (h *MetaPacketTcpHeader) extractTcpOptions(stream *ByteStream) {
	for stream.Len() >= 2 { // 如果不足2B，那么只可能是NOP或END
		switch TCPOptionKind(stream.U8()) {
		case TCPOptionKindEndList:
			return
		case TCPOptionKindNop:
			continue
		case TCPOptionKindWindowScale:
			stream.Skip(1)
			if stream.Len() > 0 {
				h.WinScale = stream.U8()
			}
		case TCPOptionKindSACKPermitted:
			stream.Skip(1)
			h.SACKPermitted = true
		case TCPOptionKindMSS:
			stream.Skip(1)
			h.MSS = stream.U16()
		case TCPOptionKindSACK:
			sackLen := int(stream.U8() - 2)
			if stream.Len() >= sackLen {
				h.Sack = make([]byte, sackLen)
				copy(h.Sack, stream.Field(sackLen))
			}
		default: // others
			stream.Skip(int(stream.U8()) - 2)
		}
	}
}

func isVlanTagged(ethType EthernetType) bool {
	return ethType == EthernetTypeQinQ || ethType == EthernetTypeDot1Q
}

func (p *MetaPacket) ParseArp(stream *ByteStream) {
	p.RawHeader = make([]byte, ARP_HEADER_SIZE)
	copy(p.RawHeader, stream.Slice())

	stream.Skip(6)
	op := stream.U16()
	p.Invalid = op == ARPReply // arp reply有代传，MAC和IP地址不对应，所以为无效包
	stream.Skip(MAC_ADDR_LEN)
	p.IpSrc = stream.U32()
	stream.Skip(MAC_ADDR_LEN)
	p.IpDst = stream.U32()
}

func (p *MetaPacket) ParseIcmp(stream *ByteStream) {
	p.RawHeader = make([]byte, 0, 36)
	p.RawHeader = append(p.RawHeader, stream.Slice()[:2]...)
	icmpType, _ := stream.U8(), stream.U8()
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
		p.RawHeader = append(p.RawHeader[:4], stream.Field(32)...)
		return
	default:
		p.RawHeader = append(p.RawHeader[:4], stream.Field(4)...)
		return
	}
}

func (p *MetaPacket) ParseL4(stream *ByteStream) {
	if p.Protocol == IPProtocolTCP {
		len := stream.Len()
		if len < MIN_TCP_HEADER_SIZE {
			p.PayloadLen = 0
			p.Invalid = true
			return
		}
		p.PortSrc = stream.U16()
		p.PortDst = stream.U16()
		seq := stream.U32()
		ack := stream.U32()
		dataOffset := uint16(stream.U8()&0xF0) >> 2
		flags := stream.U8()
		winSize := stream.U16()
		stream.Skip(4) // skip checksum and URG Pointer
		p.PayloadLen -= dataOffset
		tcpHeader := &MetaPacketTcpHeader{flags, seq, ack, uint8(dataOffset >> 2), winSize, 0, false, 0, nil}
		if optionsLen := dataOffset - MIN_TCP_HEADER_SIZE; optionsLen > 0 {
			tcpHeader.extractTcpOptions(&ByteStream{stream.Field(int(optionsLen)), 0})
		}
		p.TcpData = tcpHeader
	} else if p.Protocol == IPProtocolUDP {
		if stream.Len() < UDP_HEADER_SIZE {
			p.Invalid = true
			return
		}
		p.PortSrc = stream.U16()
		p.PortDst = stream.U16()
		p.PayloadLen = stream.U16() - UDP_HEADER_SIZE
	} else if p.Protocol == IPProtocolICMPv4 {
		p.ParseIcmp(stream)
	}
}

func (p *MetaPacket) ParseIp(stream *ByteStream) {
	ihl := (stream.U8() & 0xF)
	p.IHL = ihl
	stream.Skip(1) // skip tos
	totalLength := stream.U16()
	p.IpID = stream.U16()
	p.IpFlags = stream.U16()
	fragmentOffset := p.IpFlags & 0x1FFF
	p.TTL = stream.U8()
	p.Protocol = IPProtocol(stream.U8())
	stream.Skip(2) // skip checksum
	p.IpSrc = stream.U32()
	p.IpDst = stream.U32()
	ipOptionsSize := int(ihl)*4 - MIN_IPV4_HEADER_SIZE
	if stream.Len() <= ipOptionsSize || fragmentOffset > 0 { // no more header
		return
	}
	stream.Skip(ipOptionsSize) // skip options
	payloadLength := uint16(Min(stream.Len(), int(totalLength)-int(ihl)*4))
	if p.Protocol == IPProtocolTCP {
		p.PayloadLen = totalLength - uint16(ihl*4)
	}
	p.ParseL4(&ByteStream{stream.Slice()[:payloadLength], 0})
}

// TODO: 一个合法ip报文应当至少有30B的长度(不考虑非ip情形)
//       因此如果我们能够减少长度的判断，想必能够提升不少的性能
func (p *MetaPacket) Parse(l3Packet RawPacket) bool {
	stream := ByteStream{l3Packet, 0}

	// L3
	if p.EthType == EthernetTypeIPv4 && stream.Len() >= MIN_IPV4_HEADER_SIZE {
		p.ParseIp(&stream)
	} else if p.EthType == EthernetTypeARP && stream.Len() >= ARP_HEADER_SIZE {
		p.ParseArp(&stream)
	}

	return true
}

func (p *MetaPacket) ParseL2(packet RawPacket) int {
	stream := ByteStream{packet, 0}
	inPort := uint32(0)
	l2Len := 0

	if stream.Len() < ETH_HEADER_SIZE {
		p.Invalid = true
		return l2Len
	}

	p.MacDst = MacIntFromBytes(stream.Field(MAC_ADDR_LEN))
	p.MacSrc = MacIntFromBytes(stream.Field(MAC_ADDR_LEN))
	p.EthType = EthernetType(stream.U16())
	l2Len += ETH_HEADER_SIZE
	if isVlanTagged(p.EthType) && stream.Len() > VLANTAG_LEN+ETH_TYPE_LEN {
		vlanTag := stream.U16()
		vid := vlanTag & VLAN_ID_MASK
		if pcp := (vlanTag >> 13) & 0x7; pcp == MIRRORED_TRAFFIC {
			inPort = (uint32(vid&0xF00) << 8) | uint32(vid&0xFF)
		} else {
			p.Vlan = vid
		}
		p.EthType = EthernetType(stream.U16())
		l2Len += VLANTAG_LEN + ETH_TYPE_LEN
	}
	if p.EthType == EthernetTypeDot1Q && stream.Len() > VLANTAG_LEN+ETH_TYPE_LEN {
		p.Vlan = stream.U16() & VLAN_ID_MASK
		p.EthType = EthernetType(stream.U16())
		l2Len += VLANTAG_LEN + ETH_TYPE_LEN
	}

	if p.InPort == 0 {
		p.InPort = inPort
	}
	return l2Len
}

func (p *MetaPacket) CopyTo(other *MetaPacket) { // XXX: Shallow copy seems unsafe
	*other = *p
}

func (p *MetaPacket) String() string {
	buffer := bytes.Buffer{}
	var format string
	format = "timestamp: %d inport: 0x%x exporter: %v len: %d l2_end: %v, %v invalid: %v\n"
	buffer.WriteString(fmt.Sprintf(format, p.Timestamp, p.InPort, IpFromUint32(p.Exporter),
		p.PacketLen, p.L2End0, p.L2End1, p.Invalid))
	if p.Tunnel != nil {
		buffer.WriteString(fmt.Sprintf("\ttunnel: %s\n", p.Tunnel))
	}
	format = "\t%s -> %s type: %04x vlan-id: %d\n"
	buffer.WriteString(fmt.Sprintf(format, Uint64ToMac(p.MacSrc), Uint64ToMac(p.MacDst), uint16(p.EthType), p.Vlan))
	format = "\t%v:%d -> %v:%d proto: %v ttl: %d ihl: %d id: %d flags: 0x%01x, fragment Offset: %d payload-len: %d "
	buffer.WriteString(fmt.Sprintf(format, IpFromUint32(p.IpSrc), p.PortSrc,
		IpFromUint32(p.IpDst), p.PortDst, p.Protocol, p.TTL, p.IHL, p.IpID, p.IpFlags>>13, p.IpFlags&0x1FFF, p.PayloadLen))
	if p.TcpData != nil {
		buffer.WriteString(fmt.Sprintf("tcp: %+v", p.TcpData))
	}
	if p.EndpointData != nil {
		buffer.WriteString(fmt.Sprintf("\n\tEndpoint: %v", p.EndpointData))
	}
	if p.PolicyData != nil {
		buffer.WriteString(fmt.Sprintf("\n\tPolicy: %v", p.PolicyData))
	}

	if len(p.Raw) > 0 {
		endIndex := Min(len(p.Raw), 64)
		buffer.WriteString(fmt.Sprintf("\n\tRawPacket: %v, len: %v", hex.Dump(p.Raw[:endIndex]), len(p.Raw)))
	}
	if len(p.RawHeader) > 0 {
		endIndex := Min(len(p.RawHeader), 64)
		buffer.WriteString(fmt.Sprintf("\n\tlen: %v, RawHeader:\n%v", len(p.RawHeader), hex.Dump(p.RawHeader[:endIndex])))
	}

	return buffer.String()
}

var metaPacketPool = NewLockFreePool(func() interface{} {
	return new(MetaPacket)
})

func AcquireMetaPacket() *MetaPacket {
	m := metaPacketPool.Get().(*MetaPacket)
	m.ReferenceCount.Reset()
	return m
}

func ReleaseMetaPacket(x *MetaPacket) {
	if x.SubReferenceCount() {
		return
	}

	*x = MetaPacket{}
	metaPacketPool.Put(x)
}

func CloneMetaPacket(x *MetaPacket) *MetaPacket {
	dup := AcquireMetaPacket()
	x.CopyTo(dup)
	return dup
}
