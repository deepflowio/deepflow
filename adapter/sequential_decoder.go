package adapter

import (
	"net"
	"strings"
	"time"

	. "github.com/google/gopacket/layers"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

const (
	DELTA_TIMESTAMP_LEN = 2
	PACKET_STREAM_END   = 1<<(DELTA_TIMESTAMP_LEN*8) - 1
	UDP_BUFFER_SIZE     = 1800
	PAYLOAD_MAX         = 1500
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
	IpID       uint16
	fragOffset uint16

	// l4
	port0, port1 uint16
	dataOffset   uint8
	win          uint16
	tcpFlags     uint8
}

type SequentialDecoder struct {
	timeAdjust time.Duration
	timestamp  time.Duration
	data       ByteStream
	seq        uint32
	pflags     PacketFlag
	forward    bool
	rx, tx     Decoded
	x          *Decoded
}

func NewSequentialDecoder(data []byte, timeAdjust int64) *SequentialDecoder {
	return &SequentialDecoder{data: NewByteStream(data), timeAdjust: time.Duration(timeAdjust)}
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
	if d.forward {
		meta.MacSrc = MacIntFromBytes(x.mac0)
		meta.MacDst = MacIntFromBytes(x.mac1)
	} else {
		meta.MacSrc = MacIntFromBytes(x.mac1)
		meta.MacDst = MacIntFromBytes(x.mac0)
	}
	if x.headerType == HEADER_TYPE_ARP {
		meta.EthType = EthernetTypeARP
		meta.ParseArp(&d.data)
	} else if x.headerType < HEADER_TYPE_IPV4 {
		meta.EthType = EthernetTypeIPv4
		d.data.Skip(2)
	} else {
		meta.EthType = EthernetTypeIPv4
		d.decodeIPv4(meta)
	}
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
		x.ip0 = net.IP(d.data.Field(IP_ADDR_LEN))
	}
	if !d.pflags.IsSet(CFLAG_IP1) {
		x.ip1 = net.IP(d.data.Field(IP_ADDR_LEN))
	}
	if d.forward {
		meta.IpSrc = IpToUint32(x.ip0)
		meta.IpDst = IpToUint32(x.ip1)
	} else {
		meta.IpSrc = IpToUint32(x.ip1)
		meta.IpDst = IpToUint32(x.ip0)
	}
	if x.headerType == HEADER_TYPE_IPV4_ICMP {
		meta.Protocol = IPProtocolICMPv4
		meta.ParseIcmp(&d.data)
		return
	} else if x.headerType == HEADER_TYPE_IPV4 {
		proto := d.data.U8()
		meta.Protocol = IPProtocol(proto)
		return
	}
	d.decodeL4(meta)
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
	if x.vlan == 0 {
		meta.PayloadLen = meta.PacketLen - 14 - uint16(x.ihl*4)
	} else {
		meta.PayloadLen = meta.PacketLen - 14 - uint16(x.ihl*4) - 4
	}
	if x.headerType == HEADER_TYPE_IPV4_UDP {
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
	meta.TcpData = &MetaPacketTcpHeader{Seq: seq, Ack: ack, Flags: x.tcpFlags, WinSize: x.win, DataOffset: x.dataOffset}
	if x.dataOffset > 5 {
		optionFlag := d.data.U8()
		if optionFlag&TCP_OPT_FLAG_WIN_SCALE > 0 {
			meta.TcpData.WinScale = d.data.U8()
		}
		if optionFlag&TCP_OPT_FLAG_MSS > 0 {
			meta.TcpData.MSS = d.data.U16()
		}
		sackPermit := optionFlag&TCP_OPT_FLAG_SACK_PERMIT > 0
		if sackPermit {
			meta.TcpData.SACKPermitted = true
		}
		sackLength := int(optionFlag & TCP_OPT_FLAG_SACK)
		meta.TcpData.Sack = make([]byte, sackLength)
		copy(meta.TcpData.Sack, d.data.Field(sackLength))
	}
}

func (d *SequentialDecoder) DecodeHeader() (uint32, bool) {
	d.data.Skip(1)
	version := d.data.U8()
	if version != 1 {
		return 0, true
	}
	d.seq = d.data.U32()
	d.timestamp = time.Duration(d.data.U64())*time.Microsecond + d.timeAdjust // µs to ns
	ifMacSuffix := d.data.U32()
	return ifMacSuffix & 0xffff, false
}

func (d *SequentialDecoder) NextPacket(meta *MetaPacket) bool {
	delta := d.data.U16()
	if delta == PACKET_STREAM_END || UDP_BUFFER_SIZE-d.data.Len() > PAYLOAD_MAX {
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
