package datatype

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	. "github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/pool"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const VLAN_ID_MASK = uint16((1 << 12) - 1)
const MIRRORED_TRAFFIC = 7

type RawPacket = []byte

type MetaPacketTcpHeader struct {
	pool.ReferenceCount

	Seq           uint32
	Ack           uint32
	Flags         uint8
	DataOffset    uint8
	WinSize       uint16
	WinScale      uint8
	SACKPermitted bool
	MSS           uint16
	Sack          []byte // sack value
}

type PacketDirection uint8

const (
	CLIENT_TO_SERVER PacketDirection = iota + 1
	SERVER_TO_CLIENT
)

type MetaPacket struct {
	// 注意字节对齐!
	RawHeader []byte // total arp, or icmp header

	Timestamp    time.Duration
	EndpointData *EndpointData
	PolicyData   *PolicyData

	Hash      uint32
	InPort    uint32 // (8B)
	Exporter  IPv4Int
	PacketLen uint16
	L2End0    bool
	L2End1    bool // (8B)

	Tunnel *TunnelInfo

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

	PortSrc    uint16
	PortDst    uint16 // (8B)
	TcpData    *MetaPacketTcpHeader
	PayloadLen uint16

	Invalid   bool
	Direction PacketDirection // flowgenerator负责初始化，表明MetaPacket方向

	pool.ReferenceCount // (8B)
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

func (h *MetaPacketTcpHeader) extractTcpOptions(stream *ByteStream) bool {
	for stream.Len() >= 2 { // 如果不足2B，那么只可能是NOP或END
		switch TCPOptionKind(stream.U8()) {
		case TCPOptionKindEndList:
			return true
		case TCPOptionKindNop:
			continue
		case TCPOptionKindWindowScale:
			stream.Skip(1)
			if stream.Len() < 1 {
				return false
			}
			h.WinScale = stream.U8()
		case TCPOptionKindSACKPermitted:
			stream.Skip(1)
			h.SACKPermitted = true
		case TCPOptionKindMSS:
			stream.Skip(1)
			if stream.Len() < 2 {
				return false
			}
			h.MSS = stream.U16()
		case TCPOptionKindSACK:
			sackLen := int(stream.U8()) - 2
			if sackLen <= 0 || sackLen > 40 || stream.Len() < sackLen {
				return false
			}
			h.Sack = make([]byte, sackLen)
			copy(h.Sack, stream.Field(sackLen))
		default: // others
			otherLen := int(stream.U8()) - 2
			if otherLen < 0 || otherLen > 40 || stream.Len() < otherLen {
				return false
			}
			stream.Skip(otherLen)
		}
	}
	return true
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
	p.RawHeader = make([]byte, 0, ICMP_HEADER_SIZE+MIN_IPV4_HEADER_SIZE)
	p.RawHeader = append(p.RawHeader, stream.Slice()[:2]...)
	icmpType := stream.U8()
	stream.Skip(3)
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
		dataLen := MIN_IPV4_HEADER_SIZE
		if stream.Len() < MIN_IPV4_HEADER_SIZE {
			dataLen = stream.Len()
		}
		p.RawHeader = append(p.RawHeader[:4], stream.Field(dataLen)...)
		return
	default:
		p.RawHeader = append(p.RawHeader[:4], stream.Field(4)...)
		return
	}
}

func (p *MetaPacket) ParseL4(stream *ByteStream) {
	if p.Protocol == IPProtocolTCP {
		length := stream.Len()
		if length < MIN_TCP_HEADER_SIZE {
			p.PayloadLen = 0
			p.Invalid = true
			return
		}
		tcpHeader := AcquireTcpHeader()
		p.PortSrc = stream.U16()
		p.PortDst = stream.U16()
		tcpHeader.Seq = stream.U32()
		tcpHeader.Ack = stream.U32()
		dataOffset := uint16(stream.U8()&0xF0) >> 2
		tcpHeader.DataOffset = uint8(dataOffset >> 2)
		tcpHeader.Flags = stream.U8()
		tcpHeader.WinSize = stream.U16()
		stream.Skip(4) // skip checksum and URG Pointer
		p.PayloadLen -= dataOffset
		p.TcpData = tcpHeader

		optionsLen := int(dataOffset) - MIN_TCP_HEADER_SIZE
		if optionsLen < 0 || optionsLen > 40 || optionsLen > length-MIN_TCP_HEADER_SIZE {
			p.Invalid = true
			return
		}
		if optionsLen > 0 {
			p.Invalid = !tcpHeader.extractTcpOptions(&ByteStream{stream.Field(int(optionsLen)), 0})
			p.TcpData = tcpHeader
		}
	} else if p.Protocol == IPProtocolUDP {
		if stream.Len() < UDP_HEADER_SIZE {
			p.Invalid = true
			return
		}
		p.PortSrc = stream.U16()
		p.PortDst = stream.U16()
		p.PayloadLen = stream.U16() - UDP_HEADER_SIZE
	} else if p.Protocol == IPProtocolICMPv4 {
		if stream.Len() < ICMP_HEADER_SIZE {
			p.Invalid = true
			return
		}
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
	if ihl < 5 || totalLength < MIN_IPV4_HEADER_SIZE || totalLength < uint16(ihl*4) {
		p.Invalid = true
		return
	}

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
			if p.PacketLen > 0 {
				p.PacketLen -= (VLANTAG_LEN + ETH_TYPE_LEN)
			}
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
	format = "timestamp: %d inport: 0x%x exporter: %v len: %d l2_end: %v, %v invalid: %v direction: %v\n"
	buffer.WriteString(fmt.Sprintf(format, p.Timestamp, p.InPort, IpFromUint32(p.Exporter),
		p.PacketLen, p.L2End0, p.L2End1, p.Invalid, p.Direction))
	if p.Tunnel != nil {
		buffer.WriteString(fmt.Sprintf("\ttunnel: %s\n", p.Tunnel))
	}
	format = "\t%s -> %s type: %04x vlan-id: %d\n"
	buffer.WriteString(fmt.Sprintf(format, Uint64ToMac(p.MacSrc), Uint64ToMac(p.MacDst), uint16(p.EthType), p.Vlan))
	if p.EthType == EthernetTypeIPv6 {
		format = "\t%v.%d -> %v.%d proto: %v hop limit: %d flow lable: %d next header: %v options: %+x "
		buffer.WriteString(fmt.Sprintf(format, p.Ip6Src, p.PortSrc,
			p.Ip6Dst, p.PortDst, p.Protocol, p.TTL, uint32(p.IpFlags)|uint32(p.IHL)<<16, p.NextHeader, p.Options))
	} else {
		format = "\t%v:%d -> %v:%d proto: %v ttl: %d ihl: %d id: %d flags: 0x%01x, fragment Offset: %d payload-len: %d "
		buffer.WriteString(fmt.Sprintf(format, IpFromUint32(p.IpSrc), p.PortSrc,
			IpFromUint32(p.IpDst), p.PortDst, p.Protocol, p.TTL, p.IHL, p.IpID, p.IpFlags>>13, p.IpFlags&0x1FFF, p.PayloadLen))
	}
	if p.TcpData != nil {
		buffer.WriteString(fmt.Sprintf("tcp: %v", p.TcpData))
	}
	if p.EndpointData != nil {
		buffer.WriteString(fmt.Sprintf("\n\tEndpoint: %v", p.EndpointData))
	}
	if p.PolicyData != nil {
		buffer.WriteString(fmt.Sprintf("\n\tPolicy: %v", p.PolicyData))
		if p.EndpointData != nil {
			buffer.WriteString("\n\t" + FormatAclGidBitmap(p.EndpointData, p.PolicyData))
		}
	}

	if len(p.RawHeader) > 0 {
		endIndex := Min(len(p.RawHeader), 64)
		buffer.WriteString(fmt.Sprintf("\n\tRawHeader len: %v, RawHeader: %v", len(p.RawHeader), hex.EncodeToString(p.RawHeader[:endIndex])))
	}

	return buffer.String()
}

func (h *MetaPacketTcpHeader) String() string {
	return fmt.Sprintf("&{Flags:%v Seq:%v Ack:%v DataOffset:%v WinSize:%v WinScale:%v SACKPermitted:%v MSS:%v Sack:%v}",
		h.Flags, h.Seq, h.Ack, h.DataOffset, h.WinSize, h.WinScale, h.SACKPermitted, h.MSS, h.Sack)
}

var tcpHeaderPool = pool.NewLockFreePool(func() interface{} {
	return new(MetaPacketTcpHeader)
})

func AcquireTcpHeader() *MetaPacketTcpHeader {
	h := tcpHeaderPool.Get().(*MetaPacketTcpHeader)
	h.ReferenceCount.Reset()
	return h
}

func ReleaseTcpHeader(h *MetaPacketTcpHeader) {
	if h.SubReferenceCount() {
		return
	}

	*h = MetaPacketTcpHeader{}
	tcpHeaderPool.Put(h)
}

func CloneTcpHeader(h *MetaPacketTcpHeader) *MetaPacketTcpHeader {
	dup := AcquireTcpHeader()
	*dup = *h
	return dup
}

var metaPacketPool = pool.NewLockFreePool(func() interface{} {
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

	if x.TcpData != nil {
		ReleaseTcpHeader(x.TcpData)
	}

	*x = MetaPacket{}
	metaPacketPool.Put(x)
}

func CloneMetaPacket(x *MetaPacket) *MetaPacket {
	dup := AcquireMetaPacket()
	x.CopyTo(dup)
	return dup
}
