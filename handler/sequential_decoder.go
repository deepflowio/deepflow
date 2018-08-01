package handler

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	. "github.com/google/gopacket/layers"
	"github.com/willf/bitset"
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
	data      ByteStream
	seq       uint32
	pflags    PacketFlag
	direction string
	rx, tx    Decoded
	x         *Decoded

	stringBuffer *bytes.Buffer
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

func decodeFlags(flags PacketFlag) (string, int) {
	var stringBuffer bytes.Buffer
	if flags == PFLAG_NONE {
		return "NUL", 0
	}
	b := bitset.From([]uint64{uint64(flags)})
	compressedSize := 0
	for i, e := b.NextSet(0); e; i, e = b.NextSet(i + 1) {
		name := FLAGS_NAME[i]
		stringBuffer.WriteString(name + "|")
		compressedSize += COMPRESS_SIZE[i]
	}
	stringBuffer.Truncate(stringBuffer.Len() - 1)
	return SHORTER_FLAGS.Replace(stringBuffer.String()), compressedSize
}

func (d *SequentialDecoder) Seq() uint32 {
	return d.seq
}

func (d *SequentialDecoder) decodeTunnel() string {
	sip := net.IP(d.data.Field(IP_ADDR_LEN))
	dip := net.IP(d.data.Field(IP_ADDR_LEN))
	tunnelType := TunnelType(d.data.U8())
	tunnelId := uint32((d.data.U8()))<<16 | uint32(d.data.U16())
	return fmt.Sprintf(" %s %d %s:%s\n", tunnelType, tunnelId, sip, dip)
}

func (d *SequentialDecoder) decodeEthernet() {
	x := d.x
	sb := d.stringBuffer
	if !d.pflags.IsSet(CFLAG_MAC0) {
		x.mac0 = net.HardwareAddr(d.data.Field(MAC_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_MAC1) {
		x.mac1 = net.HardwareAddr(d.data.Field(MAC_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_VLANTAG) {
		x.vlan = d.data.U16() & 0xFFF
	}
	sb.WriteString(fmt.Sprintf(" %s %s %s", x.mac0, d.direction, x.mac1))
	if x.vlan > 0 {
		sb.WriteString(fmt.Sprintf(" vid: %d", x.vlan))
	}
	if x.headerType == HEADER_TYPE_ARP {
		sb.WriteString(fmt.Sprintf(" arp: %s", hex.EncodeToString(d.data.Field(ARP_HEADER_SIZE))))
	} else if x.headerType < HEADER_TYPE_IPV4 {
		sb.WriteString(fmt.Sprintf(" ethType: 0x%04x", d.data.U16()))
	} else {
		d.decodeIPv4()
	}
}

func (d *SequentialDecoder) decodeIPv4() {
	x := d.x
	sb := d.stringBuffer
	if !d.pflags.IsSet(CFLAG_DATAOFF_IHL) {
		b := d.data.U8()
		x.ihl = b & 0xF
		x.dataOffset = b >> 4 // XXX: Valid in TCP Only
	}
	id := d.data.U16()
	sb.WriteString(fmt.Sprintf(" ihl: %d id: %d", x.ihl, id))

	if !d.pflags.IsSet(CFLAG_FLAGS_FRAG_OFFSET) {
		value := d.data.U16()
		x.flags, x.fragOffset = uint8(value>>13), value&0x1FFF
	}
	if x.flags > 0 {
		sb.WriteString(fmt.Sprintf(" flags: %x", x.flags))
	}
	if x.fragOffset > 0 {
		sb.WriteString(fmt.Sprintf(" fragoff: %d", x.fragOffset))
	}

	if !d.pflags.IsSet(CFLAG_TTL) {
		x.ttl = d.data.U8()
	}
	sb.WriteString(fmt.Sprintf(" ttl: %d", x.ttl))
	if !d.pflags.IsSet(CFLAG_IP0) {
		x.ip0 = net.IP(d.data.Field(IP_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_IP1) {
		x.ip1 = net.IP(d.data.Field(IP_ADDR_LEN))
	}
	if x.headerType == HEADER_TYPE_IPV4_ICMP {
		icmpType, code := d.data.U8(), d.data.U8()
		sb.WriteString(fmt.Sprintf("\n\t%s %s %s", x.ip0, d.direction, x.ip1))
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
			sb.WriteString(fmt.Sprintf(" ICMP type: %d code: %d rest: %s", icmpType, code,
				hex.EncodeToString(d.data.Field(28))))
			return
		default:
			id := d.data.U16()
			seq := d.data.U16()
			sb.WriteString(fmt.Sprintf(" ICMP type: %d code: %d id: %d seq: %d", icmpType, code, id, seq))
			return
		}
	} else if x.headerType == HEADER_TYPE_IPV4 {
		proto := d.data.U8()
		sb.WriteString(fmt.Sprintf("\n\t%s %s %s proto: %d", x.ip0, d.direction, x.ip1, proto))
		return
	}
	d.decodeL4()
}

func (d *SequentialDecoder) decodeL4() {
	x := d.x
	sb := d.stringBuffer
	if !d.pflags.IsSet(CFLAG_PORT0) {
		x.port0 = d.data.U16()
	}
	if !d.pflags.IsSet(CFLAG_PORT1) {
		x.port1 = d.data.U16()
	}
	sb.WriteString(fmt.Sprintf("\n\t%s:%d %s %s:%d", x.ip0, x.port0, d.direction, x.ip1, x.port1))
	if x.headerType == HEADER_TYPE_IPV4_UDP {
		return
	}
	seq := d.data.U32()
	ack := d.data.U32()
	if !d.pflags.IsSet(CFLAG_TCP_FLAGS) {
		x.tcpFlags = d.data.U8()
	}
	if !d.pflags.IsSet(CFLAG_WIN) {
		x.win = d.data.U16()
	}
	sb.WriteString(fmt.Sprintf(" seq: %d ack: %d", seq, ack))
	if x.dataOffset > 5 {
		sb.WriteString(fmt.Sprintf(" data-offset: %d", x.dataOffset))
	}
	sb.WriteString(fmt.Sprintf(" flags: %x win: %d", x.tcpFlags, x.win))
	if x.dataOffset > 5 {
		optionFlag := d.data.U8()
		if optionFlag&TCP_OPT_FLAG_WIN_SCALE > 0 {
			sb.WriteString(fmt.Sprintf(" win-scale: %d", d.data.U8()))
		}
		if optionFlag&TCP_OPT_FLAG_MSS > 0 {
			sb.WriteString(fmt.Sprintf(" MSS: %d", d.data.U16()))
		}
		sackPermit := optionFlag&TCP_OPT_FLAG_SACK_PERMIT > 0
		if sackPermit {
			sb.WriteString(" sack-permit")
		}
		sackLength := int(optionFlag & TCP_OPT_FLAG_SACK)
		if sackLength > 0 {
			sb.WriteString(" sacks(rel):")
			for i := 0; i < sackLength; i += 8 {
				sb.WriteString(fmt.Sprintf("%d-%d,", d.data.U32()-ack+1, d.data.U32()-ack+1))
			}
			sb.Truncate(sb.Len() - 1)
		}
	}
}

func (d *SequentialDecoder) DecodeHeader() string {
	_ = d.data.U8()
	version := d.data.U8()
	d.seq = d.data.U32()
	timestamp := d.data.U64()
	ifMacSuffix := d.data.U32()
	return fmt.Sprintf(
		"version: %d, seq: %d, timestamp: %d, ifMacSuffix: %x, size: %d",
		version, d.seq, timestamp, ifMacSuffix, len(d.data),
	)
}

func (d *SequentialDecoder) NextPacket() (string, int) {
	if d.stringBuffer == nil {
		d.stringBuffer = bytes.NewBuffer(make([]byte, 1024))
	}
	sb := d.stringBuffer
	delta := d.data.U16()
	if delta == PACKET_STREAM_END {
		return "", 0
	}
	sb.Reset()
	totalSize := d.data.U16()
	d.pflags = PacketFlag(d.data.U16())
	flagsString, compressedSize := decodeFlags(d.pflags)
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
	sb.WriteString(fmt.Sprintf("delta: +%d flags: %s -%dB size: %d", delta, flagsString, compressedSize, totalSize))
	if d.pflags.IsSet(PFLAG_TUNNEL) {
		sb.WriteString(d.decodeTunnel())
	}
	d.decodeEthernet()
	return d.stringBuffer.String(), compressedSize
}
