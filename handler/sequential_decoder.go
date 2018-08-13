package handler

import (
	"net"
	"strings"
	"time"

	. "github.com/google/gopacket/layers"
)

type Decoded struct {
	// meta
	headerType HeaderType

	// l2
	mac0, mac1 net.HardwareAddr
	vlan       uint16

	// l3
	ip0, ip1   net.IP
	ihl        uint8
	ttl        uint8
	flags      uint8
	fragOffset uint16

	// l4
	port0, port1 uint16
	dataOffset   uint8
	win          uint16
	tcpFlags     uint8
}

type SequentialDecoder struct {
	timestamp time.Duration
	data      ByteStream
	seq       uint32
	pflags    PacketFlag
	direction string
	rx, tx    Decoded
	x         *Decoded
}

func NewSequentialDecoder(data []byte) *SequentialDecoder {
	return &SequentialDecoder{data: ByteStream(data)}
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

func (d *SequentialDecoder) Seq() uint32 {
	return d.seq
}

func (d *SequentialDecoder) decodeTunnel(meta *MetaPacketHeader) {
	meta.TunnelData.TunnelDst = net.IP(d.data.Field(IP_ADDR_LEN))
	meta.TunnelData.TunnelSrc = net.IP(d.data.Field(IP_ADDR_LEN))
	meta.TunnelData.TunnelId = uint32((d.data.U8()))<<16 | uint32(d.data.U16())
	meta.TunnelData.TunnelType = TunnelType(d.data.U8())
}

func (d *SequentialDecoder) decodeEthernet(meta *MetaPacketHeader) {
	x := d.x
	if !d.pflags.IsSet(CFLAG_MAC0) {
		x.mac0 = net.HardwareAddr(d.data.Field(MAC_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_MAC1) {
		x.mac1 = net.HardwareAddr(d.data.Field(MAC_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_VLANTAG) {
		x.vlan = d.data.U16() & 0xFFF
	}

	meta.L2End0 = d.pflags.IsSet(PFLAG_SRC_ENDPOINT)
	meta.L2End1 = d.pflags.IsSet(PFLAG_DST_ENDPOINT)
	meta.Vlan = x.vlan
	if d.direction == "->" {
		meta.MacSrc = x.mac0
		meta.MacDst = x.mac1
	} else {
		meta.MacSrc = x.mac1
		meta.MacDst = x.mac0
	}
	if x.headerType == HEADER_TYPE_ARP {
		meta.EthType = EthernetTypeARP
		d.data.Field(ARP_HEADER_SIZE)
	} else if x.headerType < HEADER_TYPE_IPV4 {
		meta.EthType = EthernetTypeIPv4
		d.data.U16()
	} else {
		meta.EthType = EthernetTypeIPv4
		d.decodeIPv4(meta)
	}
}

func (d *SequentialDecoder) decodeIPv4(meta *MetaPacketHeader) {
	x := d.x
	if !d.pflags.IsSet(CFLAG_DATAOFF_IHL) {
		b := d.data.U8()
		x.ihl = b & 0xF
		x.dataOffset = b >> 4 // XXX: Valid in TCP Only
	}
	d.data.U16()

	if !d.pflags.IsSet(CFLAG_FLAGS_FRAG_OFFSET) {
		value := d.data.U16()
		x.flags, x.fragOffset = uint8(value>>13), value&0x1FFF
	}

	if !d.pflags.IsSet(CFLAG_TTL) {
		x.ttl = d.data.U8()
	}
	if !d.pflags.IsSet(CFLAG_IP0) {
		x.ip0 = net.IP(d.data.Field(IP_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_IP1) {
		x.ip1 = net.IP(d.data.Field(IP_ADDR_LEN))
	}
	meta.TTL = x.ttl
	if d.direction == "->" {
		meta.IpSrc = x.ip0
		meta.IpDst = x.ip1
	} else {
		meta.IpSrc = x.ip1
		meta.IpDst = x.ip0
	}
	if x.headerType == HEADER_TYPE_IPV4_ICMP {
		meta.Proto = IPProtocolICMPv4
		icmpType, _ := d.data.U8(), d.data.U8()
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
			d.data.U32() // skip 4B
			d.data.Field(28)
			return
		default:
			d.data.U32()
			return
		}
	} else if x.headerType == HEADER_TYPE_IPV4 {
		proto := d.data.U8()
		meta.Proto = IPProtocol(proto)
		return
	}
	d.decodeL4(meta)
}

func (d *SequentialDecoder) decodeL4(meta *MetaPacketHeader) {
	x := d.x
	if !d.pflags.IsSet(CFLAG_PORT0) {
		x.port0 = d.data.U16()
	}
	if !d.pflags.IsSet(CFLAG_PORT1) {
		x.port1 = d.data.U16()
	}

	if d.direction == "->" {
		meta.PortSrc = x.port0
		meta.PortDst = x.port1
	} else {
		meta.PortSrc = x.port1
		meta.PortDst = x.port0
	}
	if x.vlan == 0 {
		meta.PayloadLen = meta.PktLen - 14 - uint16(x.ihl*4)
	} else {
		meta.PayloadLen = meta.PktLen - 14 - uint16(x.ihl*4) - 4
	}
	if x.headerType == HEADER_TYPE_IPV4_UDP {
		meta.Proto = IPProtocolUDP
		meta.PayloadLen -= 8
		return
	}
	meta.PayloadLen -= uint16(x.dataOffset * 4)
	meta.Proto = IPProtocolTCP
	seq := d.data.U32()
	ack := d.data.U32()
	meta.TcpData.Seq = seq
	meta.TcpData.Ack = ack
	if !d.pflags.IsSet(CFLAG_TCP_FLAGS) {
		x.tcpFlags = d.data.U8()
	}
	if !d.pflags.IsSet(CFLAG_WIN) {
		x.win = d.data.U16()
	}
	meta.TcpData.Flags = x.tcpFlags
	meta.TcpData.WinSize = x.win
	if x.dataOffset > 5 {
		optionFlag := d.data.U8()
		if optionFlag&TCP_OPT_FLAG_WIN_SCALE > 0 {
			meta.TcpData.WinScale = d.data.U8()
		}
		if optionFlag&TCP_OPT_FLAG_MSS > 0 {
			d.data.U16()
		}
		sackPermit := optionFlag&TCP_OPT_FLAG_SACK_PERMIT > 0
		if sackPermit {
			meta.TcpData.SACKPermitted = true
		}
		sackLength := int(optionFlag & TCP_OPT_FLAG_SACK)
		if sackLength > 0 {
			for i := 0; i < sackLength; i += 8 {
				d.data.U64()
			}
		}
	}
}

func (d *SequentialDecoder) DecodeHeader() uint32 {
	_ = d.data.U8()
	_ = d.data.U8()
	d.seq = d.data.U32()
	d.timestamp = time.Duration(d.data.U64())
	ifMacSuffix := d.data.U32()
	return ifMacSuffix & 0xffff
}

func (d *SequentialDecoder) NextPacket(meta *MetaPacketHeader) bool {
	delta := d.data.U16()
	if delta == PACKET_STREAM_END {
		return true
	}
	totalSize := d.data.U16()
	d.pflags = PacketFlag(d.data.U16())
	if d.pflags.IsSet(PFLAG_DST_ENDPOINT) {
		d.x = &d.rx
		d.direction = "<-"
	} else {
		d.x = &d.tx
		d.direction = "->"
	}
	if !d.pflags.IsSet(CFLAG_HEADER_TYPE) {
		d.x.headerType = HeaderType(d.data.U8())
	}
	d.timestamp += time.Duration(delta)
	if d.pflags.IsSet(PFLAG_TUNNEL) {
		d.decodeTunnel(meta)
	}
	meta.PktLen = totalSize
	meta.Timestamp = d.timestamp
	d.decodeEthernet(meta)
	return false
}
