package adapter

import (
	"encoding/binary"
	"net"
	"strings"
	"time"

	. "github.com/google/gopacket/layers"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

const (
	DELTA_TIMESTAMP_LEN = 2
	PACKET_STREAM_END   = 1<<(DELTA_TIMESTAMP_LEN*8) - 1
	UDP_BUFFER_SIZE     = 1 << 16
	ICMP_TYPE_CODE      = 2
	ICMP_ID_SEQ         = 4
	ICMP_REST           = 28

	IPV6_ADDR_LEN = 16
)

const (
	ANALYZER_TRIDENT      = 0xffffffe0 // 压缩报文来自analyzer上的trident
	ANALYZER_TRIDNET_MASK = 0x1f       // 压缩报文来自analyzer上的trident时的掩码
	TRIDNET_MASK          = 0xffff     // 压缩报文来自vtap上的trident时的掩码
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

	// l3 ipv6
	ip6Src, ip6Dst net.IP

	// l4
	port0, port1 uint16
	dataOffset   uint8
	win          uint16
	tcpFlags     uint8
}

type SequentialDecoder struct {
	timestamp time.Duration
	data      ByteStream
	seq       uint64
	pflags    PacketFlag
	forward   bool
	rx, tx    Decoded
	x         *Decoded

	inPort                 uint32
	tridentDispatcherIndex uint8
}

func NewSequentialDecoder(data []byte) *SequentialDecoder {
	return &SequentialDecoder{data: NewByteStream(data)}
}

func (d *SequentialDecoder) initSequentialDecoder(data []byte) {
	d.data = NewByteStream(data)
}

var FLAGS_NAME = [...]string{
	"M0",    // mac0
	"M1",    // mac1
	"V",     // vlan
	"H",     // header-type
	"A0",    // ip0
	"A1",    // ip1
	"P0",    // port0
	"P1",    // port1
	"TTL",   // ttl
	"IP_F+", // flags + frags-offset
	"IHL+",  // ihl + data-offset
	"WIN",   // win
	"TCP_F", // tcp flags
	"S",     // src-endpoint
	"D",     // dst-endpoint
	"T",     // tunnel
}

var SHORTER_FLAGS = strings.NewReplacer(
	"M0|M1|V", "L2",
	"M0|M1", "M",
	"A0|A1|P0|P1", "L3",
	"A0|A1", "IP",
	"P0|P1", "P",
	"S|D", "L", // local packet
)

var COMPRESS_SIZE = [...]int{
	MAC_ADDR_LEN,
	MAC_ADDR_LEN,
	VLANTAG_LEN,
	HEADER_TYPE_LEN,
	IP_ADDR_LEN,
	IP_ADDR_LEN,
	PORT_LEN,
	PORT_LEN,
	IPV4_TTL_LEN,
	IPV4_FLAGS_FRAG_OFFSET_LEN,
	1, // IHL_DATA_OFFSET
	TCP_WIN_LEN,
	1, // TCP_FLAGS
	0, 0, 0,
}

func (d *SequentialDecoder) Seq() uint64 {
	return d.seq
}

func decodeTunnel(stream *ByteStream) *TunnelInfo {
	src := stream.U32()
	dst := stream.U32()
	tunnelType := TunnelType(stream.U8())
	id := uint32((stream.U8()))<<16 | uint32(stream.U16())
	return &TunnelInfo{Type: tunnelType, Src: src, Dst: dst, Id: id}
}

func (d *SequentialDecoder) decodeEthernet(meta *MetaPacket) {
	x := d.x
	if !d.pflags.IsSet(CFLAG_MAC0) {
		x.mac0 = MacIntFromBytes(d.data.Field(MAC_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_MAC1) {
		x.mac1 = MacIntFromBytes(d.data.Field(MAC_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_VLANTAG) {
		x.vlan = d.data.U16() & 0xFFF
	}

	meta.L2End0 = d.pflags.IsSet(PFLAG_SRC_ENDPOINT)
	meta.L2End1 = d.pflags.IsSet(PFLAG_DST_ENDPOINT)
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
		meta.ParseArp(&d.data)
	} else if x.headerType < HEADER_TYPE_IPV4 {
		meta.EthType = EthernetType(d.data.U16())
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
		b := d.data.U8()
		x.dataOffset = b >> 4 // XXX: Valid in TCP Only
		x.ihl = b & 0xf
	}
	meta.IHL = x.ihl
	if !d.pflags.IsSet(CFLAG_FLAGS_FRAG_OFFSET) {
		x.fragOffset = d.data.U16()
	}
	meta.IpFlags = x.fragOffset
	if !d.pflags.IsSet(CFLAG_TTL) {
		x.ttl = d.data.U8()
	}
	meta.TTL = x.ttl
	if !d.pflags.IsSet(CFLAG_IP0) {
		x.ip6Src = net.IP(d.data.Field(IPV6_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_IP1) {
		x.ip6Dst = net.IP(d.data.Field(IPV6_ADDR_LEN))
	}
	meta.Ip6Src = make(net.IP, 16)
	meta.Ip6Dst = make(net.IP, 16)
	if d.forward {
		copy(meta.Ip6Src, x.ip6Src)
		copy(meta.Ip6Dst, x.ip6Dst)
	} else {
		copy(meta.Ip6Src, x.ip6Dst)
		copy(meta.Ip6Dst, x.ip6Src)
	}
	meta.NextHeader = IPProtocol(d.data.U8())
	if length := d.data.U8(); length > 0 {
		meta.Options = d.data.Field(int(length))
	}
	if x.headerType == HEADER_TYPE_IPV6 {
		meta.Protocol = meta.NextHeader
		return
	}
	d.decodeL4(meta)
}

func (d *SequentialDecoder) decodeIPv4(meta *MetaPacket) {
	x := d.x
	if !d.pflags.IsSet(CFLAG_DATAOFF_IHL) {
		b := d.data.U8()
		x.ihl = b & 0xF
		x.dataOffset = b >> 4 // XXX: Valid in TCP Only
	}
	meta.IHL = x.ihl
	x.IpID = d.data.U16()
	meta.IpID = x.IpID

	if !d.pflags.IsSet(CFLAG_FLAGS_FRAG_OFFSET) {
		value := d.data.U16()
		x.flags, x.fragOffset = uint8(value>>13), value&0x1FFF
	}
	meta.IpFlags = uint16(x.flags<<13) | x.fragOffset

	if !d.pflags.IsSet(CFLAG_TTL) {
		x.ttl = d.data.U8()
	}
	meta.TTL = x.ttl

	if !d.pflags.IsSet(CFLAG_IP0) {
		x.ip0 = binary.BigEndian.Uint32(d.data.Field(IP_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_IP1) {
		x.ip1 = binary.BigEndian.Uint32(d.data.Field(IP_ADDR_LEN))
	}
	if d.forward {
		meta.IpSrc = x.ip0
		meta.IpDst = x.ip1
	} else {
		meta.IpSrc = x.ip1
		meta.IpDst = x.ip0
	}
	if x.headerType == HEADER_TYPE_IPV4_ICMP {
		meta.Protocol = IPProtocolICMPv4
		d.decodeICMP(meta)
		return
	} else if x.headerType == HEADER_TYPE_IPV4 {
		proto := d.data.U8()
		meta.Protocol = IPProtocol(proto)
		return
	}
	d.decodeL4(meta)
}

func (d *SequentialDecoder) decodeICMP(meta *MetaPacket) {
	stream := &d.data
	meta.RawHeader = make([]byte, ICMP_HEADER_SIZE+ICMP_REST)
	icmpType, icmpCode := stream.U8(), stream.U8()
	meta.RawHeader[0] = icmpType
	meta.RawHeader[1] = icmpCode
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
		dataLen := ICMP_ID_SEQ + ICMP_REST
		if stream.Len() < dataLen {
			dataLen = stream.Len()
		}
		meta.RawHeader = append(meta.RawHeader[:4], stream.Field(dataLen)...)
		return
	default:
		meta.RawHeader = append(meta.RawHeader[:4], stream.Field(ICMP_ID_SEQ)...)
		return
	}
}

func (d *SequentialDecoder) decodeL4(meta *MetaPacket) {
	x := d.x
	if !d.pflags.IsSet(CFLAG_PORT0) {
		x.port0 = d.data.U16()
	}
	if !d.pflags.IsSet(CFLAG_PORT1) {
		x.port1 = d.data.U16()
	}

	if d.forward {
		meta.PortSrc = x.port0
		meta.PortDst = x.port1
	} else {
		meta.PortSrc = x.port1
		meta.PortDst = x.port0
	}
	l3Len := 0
	if x.headerType.IsIpv6() {
		l3Len = 40 + len(meta.Options)
	} else {
		l3Len = int(x.ihl * 4)
	}
	if x.vlan == 0 {
		meta.PayloadLen = meta.PacketLen - 14 - uint16(l3Len)
	} else {
		meta.PayloadLen = meta.PacketLen - 14 - uint16(l3Len) - 4
	}
	if x.headerType == HEADER_TYPE_IPV4_UDP || x.headerType == HEADER_TYPE_IPV6_UDP {
		meta.Protocol = IPProtocolUDP
		meta.PayloadLen -= 8
		return
	}
	meta.PayloadLen -= uint16(x.dataOffset * 4)
	meta.Protocol = IPProtocolTCP
	seq := d.data.U32()
	ack := d.data.U32()
	if !d.pflags.IsSet(CFLAG_TCP_FLAGS) {
		x.tcpFlags = d.data.U8()
	}
	if !d.pflags.IsSet(CFLAG_WIN) {
		x.win = d.data.U16()
	}
	tcpData := &meta.TcpData
	tcpData.Seq = seq
	tcpData.Ack = ack
	tcpData.Flags = x.tcpFlags
	tcpData.WinSize = x.win
	tcpData.DataOffset = x.dataOffset
	if x.dataOffset > 5 {
		optionFlag := d.data.U8()
		if optionFlag&TCP_OPT_FLAG_WIN_SCALE > 0 {
			tcpData.WinScale = d.data.U8()
		}
		if optionFlag&TCP_OPT_FLAG_MSS > 0 {
			tcpData.MSS = d.data.U16()
		}
		sackPermit := optionFlag&TCP_OPT_FLAG_SACK_PERMIT > 0
		if sackPermit {
			tcpData.SACKPermitted = true
		}
		sackLength := int(optionFlag & TCP_OPT_FLAG_SACK)
		if sackLength > 0 {
			tcpData.Sack = make([]byte, sackLength)
			copy(tcpData.Sack, d.data.Field(sackLength))
		}
	}
}

func (d *SequentialDecoder) DecodeHeader() bool {
	d.data.Skip(1)
	version := d.data.U8()
	if version != 2 {
		return true
	}
	d.seq = d.data.U64()
	indexAndTimestamp := d.data.U64()
	index := uint8(indexAndTimestamp >> 56)
	if index >= 16 { // Trident最大16个队列[0, 15]
		return true
	}
	d.timestamp = time.Duration(indexAndTimestamp&0xffffffffffffff) * time.Microsecond
	inPort := d.data.U32()
	if inPort&ANALYZER_TRIDENT == ANALYZER_TRIDENT {
		inPort = inPort & ANALYZER_TRIDNET_MASK
		if TapType(inPort) == TAP_TOR {
			inPort = PACKET_SOURCE_TOR
		} else {
			inPort = PACKET_SOURCE_ISP | inPort
		}
	} else {
		inPort = inPort&TRIDNET_MASK | PACKET_SOURCE_TOR
	}
	d.inPort = inPort
	d.tridentDispatcherIndex = index
	return false
}

func (d *SequentialDecoder) NextPacket(meta *MetaPacket) bool {
	delta := d.data.U16()
	if delta == PACKET_STREAM_END {
		return true
	}
	totalSize := d.data.U16()
	d.pflags = PacketFlag(d.data.U16())
	if d.pflags.IsSet(PFLAG_DST_ENDPOINT) {
		d.x = &d.rx
		d.forward = false
	} else {
		d.x = &d.tx
		d.forward = true
	}
	if !d.pflags.IsSet(CFLAG_HEADER_TYPE) {
		d.x.headerType = HeaderType(d.data.U8())
	}
	d.timestamp += time.Duration(delta) * time.Microsecond // µs to ns
	if d.pflags.IsSet(PFLAG_TUNNEL) {
		meta.Tunnel = decodeTunnel(&d.data)
	}
	meta.PacketLen = totalSize
	meta.Timestamp = d.timestamp
	d.decodeEthernet(meta)
	return false
}
