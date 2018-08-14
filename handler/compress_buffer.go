package handler

import (
	. "encoding/binary"
	"unsafe"
)

type Compressed struct {
	pflags        PacketFlag
	headerType    HeaderType
	vlanTag       uint32
	mac0, mac1    uint64
	ip0, ip1      uint64
	port0, port1  uint32
	fragOffset    uint32
	tcpWin        uint32
	ttl           uint16
	dataOffsetIhl uint16
	tcpFlags      uint16
}

var EMPTY_COMPRESSED = Compressed{
	pflags:        PFLAG_NONE,
	headerType:    HEADER_TYPE_INVALID,
	mac0:          1 << MAC_ADDR_LEN * 8,
	mac1:          1 << MAC_ADDR_LEN * 8,
	vlanTag:       1 << VLANTAG_LEN * 8,
	ip0:           1 << IP_ADDR_LEN * 8,
	ip1:           1 << IP_ADDR_LEN * 8,
	port0:         1 << PORT_LEN * 8,
	port1:         1 << PORT_LEN * 8,
	fragOffset:    1 << IPV4_FLAGS_FRAG_OFFSET_LEN * 8,
	ttl:           1 << IPV4_TTL_LEN * 8,
	dataOffsetIhl: 1 << 8,
	tcpWin:        1 << TCP_WIN_LEN * 8,
	tcpFlags:      1 << 8,
}

func (c *Compressed) reset() {
	*c = EMPTY_COMPRESSED
}

type CompressBuffer struct {
	buf    []byte
	offset int
	delta  int64

	prevTimestamp  int64
	deltaTimestamp int64
	rx, tx         Compressed
	compress       *Compressed
}

func NewCompressBuffer(bufSize, initialOffset int) *CompressBuffer {
	b := new(CompressBuffer)
	b.buf = make([]byte, bufSize)
	b.reset(initialOffset)
	return b
}

func (b *CompressBuffer) reset(initialOffset int) {
	b.offset = initialOffset
	// Skip 1B reservation
	b.buf[b.offset+RESERVED_LEN] = byte(VERSION_SEQUENTIAL_COMPRESS)
	// 4B sequence + 8B initial timestamp: set before flush
	b.offset += COMPRESS_HEADER_SIZE

	b.delta = 0
	b.prevTimestamp = 0
	b.deltaTimestamp = 0
	b.rx.reset()
	b.tx.reset()
}

// 仅用于本文件比较MAC地址，因此使用主机序
func mac2NativeUint64(mac []byte) uint64 {
	return uint64(Native.Uint32(mac))<<16 | uint64(Native.Uint16(mac[4:]))
}

func (b *CompressBuffer) compressPrepare(packet []byte, meta *MetaPacket) int {
	if meta.dstEndpoint {
		b.compress = &b.rx
	} else {
		b.compress = &b.tx
	}

	c := b.compress
	c.pflags = PFLAG_NONE

	headerSize := MAX_COMPRESSED_PACKET_SIZE[meta.headerType] + meta.TcpOptionsSize()

	if meta.TunnelType != TUNNEL_TYPE_NONE {
		headerSize += LAYER_TUNNEL_SIZE
	}

	if b.prevTimestamp > 0 {
		b.delta = meta.timestamp - b.prevTimestamp
	}

	if c.headerType == HEADER_TYPE_INVALID { // the first packet
		return headerSize
	}

	if c.headerType == meta.headerType {
		c.pflags |= CFLAG_HEADER_TYPE
	}

	if meta.vlanTagSize > 0 {
		if c.vlanTag == uint32(Native.Uint16(packet[FIELD_VLANTAG_OFFSET:])) {
			c.pflags |= CFLAG_VLANTAG
		}
	} else {
		if c.vlanTag == 0 {
			c.pflags |= CFLAG_VLANTAG
		}
	}

	if c.mac0 == mac2NativeUint64(packet[meta.offsetMac0:]) {
		c.pflags |= CFLAG_MAC0
	}
	if c.mac1 == mac2NativeUint64(packet[meta.offsetMac1:]) {
		c.pflags |= CFLAG_MAC1
	}
	if meta.headerType < HEADER_TYPE_L3 {
		return headerSize - c.pflags.compressedSize()
	}

	if c.ip0 == uint64(Native.Uint32(packet[meta.offsetIp0:])) {
		c.pflags |= CFLAG_IP0
	}
	if c.ip1 == uint64(Native.Uint32(packet[meta.offsetIp1:])) {
		c.pflags |= CFLAG_IP1
	}

	if c.dataOffsetIhl == uint16(meta.dataOffsetIhl) {
		c.pflags |= CFLAG_DATAOFF_IHL
	}

	if c.ttl == uint16(packet[FIELD_TTL_OFFSET+meta.vlanTagSize]) {
		c.pflags |= CFLAG_TTL
	}

	if c.fragOffset == uint32(Native.Uint16(packet[FIELD_FRAG_OFFSET+meta.vlanTagSize:])) {
		c.pflags |= CFLAG_FLAGS_FRAG_OFFSET
	}

	if meta.headerType == HEADER_TYPE_IPV4_ICMP {
		return headerSize + meta.l4OptSize - c.pflags.compressedSize()
	} else if meta.headerType < HEADER_TYPE_L4 {
		return headerSize - c.pflags.compressedSize()
	}

	if c.port0 == uint32(Native.Uint16(packet[meta.offsetPort0:])) {
		c.pflags |= CFLAG_PORT0
	}
	if c.port1 == uint32(Native.Uint16(packet[meta.offsetPort1:])) {
		c.pflags |= CFLAG_PORT1
	}

	if meta.headerType == HEADER_TYPE_IPV4_TCP {
		if c.tcpWin == uint32(Native.Uint16(packet[FIELD_TCP_WIN_OFFSET+meta.l2L3OptSize:])) {
			c.pflags |= CFLAG_WIN
		}

		if c.tcpFlags == uint16(packet[FIELD_TCP_FLAG_OFFSET+meta.l2L3OptSize]) {
			c.pflags |= CFLAG_TCP_FLAGS
		}
	}
	return headerSize - c.pflags.compressedSize()
}

func (b *CompressBuffer) preAppendParse(packet []byte, meta *MetaPacket) bool {
	headerSize := b.compressPrepare(packet, meta)

	remain := len(b.buf) - b.offset
	require := META_PACKET_MIN_LEN + headerSize + DELTA_TIMESTAMP_LEN
	noMoreSpace := remain < require
	tooSmallDelta := b.delta < 0
	tooBigDelta := b.delta >= PACKET_STREAM_END
	notAppliableDelta := tooSmallDelta || tooBigDelta // compiler hint
	return noMoreSpace || notAppliableDelta
}

func (b *CompressBuffer) appendPacket(packet []byte, meta *MetaPacket) {
	buffer := b.buf
	offset := b.offset

	b.deltaTimestamp += b.delta

	c := b.compress

	b.prevTimestamp = meta.timestamp

	if meta.TunnelType != TUNNEL_TYPE_NONE {
		c.pflags |= PFLAG_TUNNEL
	}
	if meta.srcEndpoint {
		c.pflags |= PFLAG_SRC_ENDPOINT
	}
	if meta.dstEndpoint {
		c.pflags |= PFLAG_DST_ENDPOINT
	}

	// meta
	BigEndian.PutUint16(buffer[offset:], uint16(b.delta))
	BigEndian.PutUint16(buffer[offset+2:], uint16(meta.packetSize))
	BigEndian.PutUint16(buffer[offset+4:], uint16(c.pflags))
	offset += 6
	if !c.pflags.IsSet(CFLAG_HEADER_TYPE) {
		buffer[offset] = byte(meta.headerType)
		c.headerType = meta.headerType
		offset++
	}

	// TUNNEL
	if c.pflags.IsSet(PFLAG_TUNNEL) {
		CopyField(buffer[offset:], meta.TunnelSrc, IP_ADDR_LEN)
		CopyField(buffer[offset+IP_ADDR_LEN:], meta.TunnelDst, IP_ADDR_LEN)
		BigEndian.PutUint32(buffer[offset+IP_ADDR_LEN*2:], meta.TunnelId) // lower 3B valid
		buffer[offset+IP_ADDR_LEN*2] = byte(meta.TunnelType)              // overwrite
		offset += LAYER_TUNNEL_SIZE
	}

	// ETH
	if !c.pflags.IsSet(CFLAG_MAC0) {
		c.mac0 = mac2NativeUint64(packet[meta.offsetMac0:])
		CopyMac(buffer[offset:], packet[meta.offsetMac0:])
		offset += MAC_ADDR_LEN
	}
	if !c.pflags.IsSet(CFLAG_MAC1) {
		c.mac1 = mac2NativeUint64(packet[meta.offsetMac1:])
		CopyMac(buffer[offset:], packet[meta.offsetMac1:])
		offset += MAC_ADDR_LEN
	}
	if !c.pflags.IsSet(CFLAG_VLANTAG) {
		if meta.vlanTagSize != 0 {
			c.vlanTag = uint32(Native.Uint16(packet[FIELD_VLANTAG_OFFSET:]))
			offset += CopyField(buffer[offset:], packet[FIELD_VLANTAG_OFFSET:], VLANTAG_LEN)
		} else {
			c.vlanTag = 0
			*(*uint16)(unsafe.Pointer(&buffer[offset])) = 0
			offset += VLANTAG_LEN
		}
	}

	if meta.headerType == HEADER_TYPE_ARP {
		offset += BytesCopy(buffer[offset:], packet[FIELD_ARP_OFFSET+meta.vlanTagSize:], ARP_HEADER_SIZE)
		b.offset = offset
		return
	} else if meta.headerType < HEADER_TYPE_L3 {
		offset += CopyField(buffer[offset:], packet[FIELD_ETH_TYPE_OFFSET+meta.vlanTagSize:], ETH_TYPE_LEN)
		b.offset = offset
		return
	}

	// IPV4
	if !c.pflags.IsSet(CFLAG_DATAOFF_IHL) {
		c.dataOffsetIhl = uint16(meta.dataOffsetIhl)
		buffer[offset] = meta.dataOffsetIhl
		offset++
	}
	offset += CopyField(buffer[offset:], packet[FIELD_ID_OFFSET+meta.vlanTagSize:], FIELD_ID_LEN)
	if !c.pflags.IsSet(CFLAG_FLAGS_FRAG_OFFSET) {
		c.fragOffset = uint32(Native.Uint16(packet[FIELD_FRAG_OFFSET+meta.vlanTagSize:]))
		offset += CopyField(buffer[offset:], packet[FIELD_FRAG_OFFSET+meta.vlanTagSize:], FIELD_FRAG_LEN)
	}
	if !c.pflags.IsSet(CFLAG_TTL) {
		ttl := packet[FIELD_TTL_OFFSET+meta.vlanTagSize]
		c.ttl = uint16(ttl)
		buffer[offset] = ttl
		offset++
	}
	if !c.pflags.IsSet(CFLAG_IP0) {
		c.ip0 = uint64(Native.Uint32(packet[meta.offsetIp0:]))
		offset += CopyField(buffer[offset:], packet[meta.offsetIp0:], IP_ADDR_LEN)
	}
	if !c.pflags.IsSet(CFLAG_IP1) {
		c.ip1 = uint64(Native.Uint32(packet[meta.offsetIp1:]))
		offset += CopyField(buffer[offset:], packet[meta.offsetIp1:], IP_ADDR_LEN)
	}
	if meta.headerType == HEADER_TYPE_IPV4_ICMP {
		offset += CopyField(buffer[offset:], packet[FIELD_ICMP_TYPE_CODE_OFFSET+meta.l2L3OptSize:],
			FIELD_ICMP_TYPE_CODE_LEN)
		b.offset = offset + BytesCopy(buffer[offset:], packet[FIELD_ICMP_ID_SEQ_OFFSET+meta.l2L3OptSize:],
			FIELD_ICMP_ID_SEQ_LEN+meta.l4OptSize)
		return
	} else if meta.headerType < HEADER_TYPE_L4 {
		b.offset = offset + CopyField(buffer[offset:], packet[FIELD_PROTO_OFFSET+meta.vlanTagSize:], IPV4_PROTO_LEN)
		return
	}

	// TCP, UDP
	if !c.pflags.IsSet(CFLAG_PORT0) {
		c.port0 = uint32(Native.Uint16(packet[meta.offsetPort0:]))
		offset += CopyField(buffer[offset:], packet[meta.offsetPort0:], PORT_LEN)
	}
	if !c.pflags.IsSet(CFLAG_PORT1) {
		c.port1 = uint32(Native.Uint16(packet[meta.offsetPort1:]))
		offset += CopyField(buffer[offset:], packet[meta.offsetPort1:], PORT_LEN)
	}
	if meta.headerType == HEADER_TYPE_IPV4_TCP {
		offset += CopyField(buffer[offset:], packet[FIELD_TCP_SEQ_OFFSET+meta.l2L3OptSize:], FIELD_TCP_SEQ_LEN)
		offset += CopyField(buffer[offset:], packet[FIELD_TCP_ACK_OFFSET+meta.l2L3OptSize:], FIELD_TCP_ACK_LEN)
		if !c.pflags.IsSet(CFLAG_TCP_FLAGS) {
			tcpFlags := packet[FIELD_TCP_FLAG_OFFSET+meta.l2L3OptSize]
			c.tcpFlags = uint16(tcpFlags)
			buffer[offset] = tcpFlags
			offset++
		}
		if !c.pflags.IsSet(CFLAG_WIN) {
			c.tcpWin = uint32(Native.Uint16(packet[FIELD_TCP_WIN_OFFSET+meta.l2L3OptSize:]))
			offset += CopyField(buffer[offset:], packet[FIELD_TCP_WIN_OFFSET+meta.l2L3OptSize:], TCP_WIN_LEN)
		}
		if meta.l4OptSize > 0 {
			buffer[offset] = meta.tcpOptionsFlag
			offset++
			if meta.tcpOptionsFlag&TCP_OPT_FLAG_WIN_SCALE != 0 {
				buffer[offset] = packet[meta.tcpOptWinScaleOffset]
				offset++
			}
			if meta.tcpOptionsFlag&TCP_OPT_FLAG_MSS != 0 {
				offset += CopyField(buffer[offset:], packet[meta.tcpOptMssOffset:], TCP_OPT_MSS_LEN-2)
			}
			if meta.tcpOptionsFlag&TCP_OPT_FLAG_SACK != 0 {
				offset += BytesCopy(buffer[offset:], packet[meta.tcpOptSackOffset:], int(meta.tcpOptionsFlag&TCP_OPT_FLAG_SACK))
			}
		}
	}

	b.offset = offset
	return
}

func (b *CompressBuffer) BaseTimestamp() int64 {
	return b.prevTimestamp - b.deltaTimestamp
}
