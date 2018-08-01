package handler

import (
	"container/list"
	"encoding/binary"
	"sync"
	"time"
)

const (
	FLUSH_INTERVAL = 1 * time.Second
)

var (
	lock        *sync.Mutex
	compressors *list.List
)

type PacketFlag uint16

func (f PacketFlag) IsSet(flag PacketFlag) bool {
	return f&flag != 0
}

const (
	CFLAG_MAC0 PacketFlag = 1 << iota
	CFLAG_MAC1
	CFLAG_VLANTAG
	CFLAG_HEADER_TYPE

	CFLAG_IP0
	CFLAG_IP1
	CFLAG_PORT0
	CFLAG_PORT1

	CFLAG_TTL
	CFLAG_FLAGS_FRAG_OFFSET
	CFLAG_DATAOFF_IHL
	CFLAG_WIN

	CFLAG_TCP_FLAGS
	PFLAG_SRC_ENDPOINT
	PFLAG_DST_ENDPOINT
	PFLAG_TUNNEL

	PFLAG_NONE PacketFlag = 0
	CFLAG_FULL            = 0x1FFF
)

var cflagCompressSize = [CFLAG_FULL + 1]int{
	CFLAG_MAC0:              MAC_ADDR_LEN,
	CFLAG_MAC1:              MAC_ADDR_LEN,
	CFLAG_VLANTAG:           VLANTAG_LEN,
	CFLAG_HEADER_TYPE:       HEADER_TYPE_LEN,
	CFLAG_IP0:               IP_ADDR_LEN,
	CFLAG_IP1:               IP_ADDR_LEN,
	CFLAG_PORT0:             PORT_LEN,
	CFLAG_PORT1:             PORT_LEN,
	CFLAG_TTL:               1,
	CFLAG_FLAGS_FRAG_OFFSET: FIELD_LEN[FIELD_FRAG],
	CFLAG_DATAOFF_IHL:       1,
	CFLAG_WIN:               TCP_WIN_LEN,
	CFLAG_TCP_FLAGS:         1,
}

func (f PacketFlag) compressedSize() int {
	return cflagCompressSize[f&CFLAG_FULL]
}

type FormatVersion uint8

const (
	VERSION_SEQUENTIAL_COMPRESS FormatVersion = 1
)

const (
	RESERVED_LEN         = 1
	COMPRESS_VERSION_LEN = 1
	SEQUENCE_LEN         = 4
	TIMESTAMP_LEN        = 8
	IF_MAC_SUFFIX_LEN    = 4

	TIMESTAMP_OFFSET     = RESERVED_LEN + COMPRESS_VERSION_LEN + SEQUENCE_LEN
	IF_MAC_SUFFIX_OFFSET = TIMESTAMP_OFFSET + TIMESTAMP_LEN

	COMPRESS_HEADER_SIZE = IF_MAC_SUFFIX_OFFSET + IF_MAC_SUFFIX_LEN

	DELTA_TIMESTAMP_LEN = 2
	PACKET_SIZE_LEN     = 2
	PFLAGS_LEN          = 2
	META_PACKET_MIN_LEN = DELTA_TIMESTAMP_LEN + PACKET_SIZE_LEN + PFLAGS_LEN
)

const (
	PACKET_STREAM_END = 1<<(DELTA_TIMESTAMP_LEN*8) - 1
)

type CompressorCounter struct {
	In       uint64 `statsd:"in"`
	InBytes  uint64 `statsd:"in_bytes"`
	Out      uint64 `statsd:"out"`
	OutBytes uint64 `statsd:"out_bytes"`
}

type SequentialCompressor struct {
	sync.Mutex

	macSuffix   uint32
	reserveSize int
	bufSize     int
	ch          chan<- []byte
	Sent        bool
	buffer      *CompressBuffer // critical resource
	nextBuffer  *CompressBuffer
	counter     *CompressorCounter
}

func NewSequentialCompressor(macSuffix uint32, reserveSize, bufSize int, ch chan<- []byte) *SequentialCompressor {
	c := new(SequentialCompressor)
	c.macSuffix = macSuffix
	c.reserveSize = reserveSize
	c.bufSize = bufSize
	c.ch = ch

	c.Sent = false
	c.buffer = NewCompressBuffer(c.bufSize, c.reserveSize)
	c.nextBuffer = NewCompressBuffer(c.bufSize, c.reserveSize)
	c.counter = &CompressorCounter{}
	lock.Lock()
	compressors.PushBack(c)
	lock.Unlock()
	return c
}

func (c *SequentialCompressor) Close() {
	lock.Lock()
	for it := compressors.Front(); it != nil; it = it.Next() {
		if c == it.Value {
			compressors.Remove(it)
		}
	}
	lock.Unlock()
}

func (c *SequentialCompressor) GetCounter() interface{} {
	counter := &CompressorCounter{}
	c.counter, counter = counter, c.counter
	return counter
}

// thread-safe
func (c *SequentialCompressor) flush() bool {
	if c.buffer.prevTimestamp == 0 { // no packet
		return false
	}

	c.Lock()
	c.buffer, c.nextBuffer = c.nextBuffer, c.buffer
	c.flushCompressBuffer(c.nextBuffer)
	c.Unlock()
	return true
}

func (c *SequentialCompressor) flushCompressBuffer(fb *CompressBuffer) {
	binary.BigEndian.PutUint64(fb.buf[c.reserveSize+TIMESTAMP_OFFSET:], uint64(fb.BaseTimestamp()))
	binary.BigEndian.PutUint32(fb.buf[c.reserveSize+IF_MAC_SUFFIX_OFFSET:], c.macSuffix)
	binary.BigEndian.PutUint16(fb.buf[fb.offset:], PACKET_STREAM_END)

	c.ch <- fb.buf[:c.reserveSize+AlignUp(fb.offset-c.reserveSize+DELTA_TIMESTAMP_LEN)]
	c.Sent = true
	c.counter.Out++
	c.counter.OutBytes += uint64(fb.offset + DELTA_TIMESTAMP_LEN)

	fb.buf = make([]byte, c.bufSize)
	fb.reset(c.reserveSize)
}

func (b *CompressBuffer) accept(packet []byte, meta *MetaPacket) bool {
	return true
}

func (c *SequentialCompressor) Handle(packet []byte, meta *MetaPacket) bool {
	return true
}

func init() {
	lock = &sync.Mutex{}
	compressors = list.New()

	flushTicker := time.NewTicker(time.Duration(FLUSH_INTERVAL))
	go func() {
		for range flushTicker.C {
			lock.Lock()
			for it := compressors.Front(); it != nil; it = it.Next() {
				c := it.Value.(*SequentialCompressor)
				if c.Sent {
					c.Sent = false
				} else {
					c.flush()
				}
			}
			lock.Unlock()
		}
	}()

	for cflag := CFLAG_MAC0; cflag <= CFLAG_FULL; cflag++ {
		if cflagCompressSize[cflag] > 0 {
			continue
		}
		size := 0
		for bits := cflag; bits > 0; {
			bit := (^bits + 1) & bits
			bits ^= bit
			size += cflagCompressSize[bit]
		}
		cflagCompressSize[cflag] = size
	}
}
