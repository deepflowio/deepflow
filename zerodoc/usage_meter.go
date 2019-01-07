package zerodoc

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type UsageMeter struct {
	UsageMeterSum
	UsageMeterMax
}

func (m *UsageMeter) SortKey() uint64 {
	return m.UsageMeterSum.SumPacketTx + m.UsageMeterSum.SumPacketRx
}

func (m *UsageMeter) Encode(encoder *codec.SimpleEncoder) {
	m.UsageMeterSum.Encode(encoder)
	m.UsageMeterMax.Encode(encoder)
}

func (m *UsageMeter) Decode(decoder *codec.SimpleDecoder) {
	m.UsageMeterSum.Decode(decoder)
	m.UsageMeterMax.Decode(decoder)
}

func (m *UsageMeter) ConcurrentMerge(other app.Meter) {
	if um, ok := other.(*UsageMeter); ok {
		m.UsageMeterSum.concurrentMerge(&um.UsageMeterSum)
		m.UsageMeterMax.concurrentMerge(&um.UsageMeterMax)
	}
}

func (m *UsageMeter) SequentialMerge(other app.Meter) {
	if um, ok := other.(*UsageMeter); ok {
		m.UsageMeterSum.sequentialMerge(&um.UsageMeterSum)
		m.UsageMeterMax.sequentialMerge(&um.UsageMeterMax)
	}
}

func (m *UsageMeter) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *UsageMeter) MarshalTo(b []byte) int {
	offset := 0

	// sum
	sum := m.UsageMeterSum
	offset += copy(b[offset:], "sum_packet_tx=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumPacketTx, 10))
	offset += copy(b[offset:], "i,sum_packet_rx=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumPacketRx, 10))
	offset += copy(b[offset:], "i,sum_packet=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumPacketTx+sum.SumPacketRx, 10))
	offset += copy(b[offset:], "i,sum_bit_tx=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumBitTx, 10))
	offset += copy(b[offset:], "i,sum_bit_rx=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumBitRx, 10))
	offset += copy(b[offset:], "i,sum_bit=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumBitTx+sum.SumBitRx, 10))

	// max
	max := m.UsageMeterMax
	offset += copy(b[offset:], "i,max_packet_tx=")
	offset += copy(b[offset:], strconv.FormatUint(max.MaxPacketTx, 10))
	offset += copy(b[offset:], "i,max_packet_rx=")
	offset += copy(b[offset:], strconv.FormatUint(max.MaxPacketRx, 10))
	offset += copy(b[offset:], "i,max_packet=")
	offset += copy(b[offset:], strconv.FormatUint(max.MaxPacket, 10))
	offset += copy(b[offset:], "i,max_bit_tx=")
	offset += copy(b[offset:], strconv.FormatUint(max.MaxBitTx, 10))
	offset += copy(b[offset:], "i,max_bit_rx=")
	offset += copy(b[offset:], strconv.FormatUint(max.MaxBitRx, 10))
	offset += copy(b[offset:], "i,max_bit=")
	offset += copy(b[offset:], strconv.FormatUint(max.MaxBit, 10))
	b[offset] = 'i'
	offset++

	return offset
}

type UsageMeterSum struct {
	SumPacketTx uint64 `db:"sum_packet_tx"`
	SumPacketRx uint64 `db:"sum_packet_rx"`
	SumBitTx    uint64 `db:"sum_bit_tx"`
	SumBitRx    uint64 `db:"sum_bit_rx"`
}

func (m *UsageMeterSum) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU64(m.SumPacketTx)
	encoder.WriteU64(m.SumPacketRx)
	encoder.WriteU64(m.SumBitTx)
	encoder.WriteU64(m.SumBitRx)
}

func (m *UsageMeterSum) Decode(decoder *codec.SimpleDecoder) {
	m.SumPacketTx = decoder.ReadU64()
	m.SumPacketRx = decoder.ReadU64()
	m.SumBitTx = decoder.ReadU64()
	m.SumBitRx = decoder.ReadU64()
}

func (m *UsageMeterSum) concurrentMerge(other *UsageMeterSum) {
	m.SumPacketTx += other.SumPacketTx
	m.SumPacketRx += other.SumPacketRx
	m.SumBitTx += other.SumBitTx
	m.SumBitRx += other.SumBitRx
}

func (m *UsageMeterSum) sequentialMerge(other *UsageMeterSum) {
	m.concurrentMerge(other)
}

type UsageMeterMax struct {
	MaxPacketTx uint64 `db:"max_packet_tx"`
	MaxPacketRx uint64 `db:"max_packet_rx"`
	MaxPacket   uint64 `db:"max_packet"`
	MaxBitTx    uint64 `db:"max_bit_tx"`
	MaxBitRx    uint64 `db:"max_bit_rx"`
	MaxBit      uint64 `db:"max_bit"`
}

func (m *UsageMeterMax) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU64(m.MaxPacketTx)
	encoder.WriteU64(m.MaxPacketRx)
	encoder.WriteU64(m.MaxPacket)
	encoder.WriteU64(m.MaxBitTx)
	encoder.WriteU64(m.MaxBitRx)
	encoder.WriteU64(m.MaxBit)
}

func (m *UsageMeterMax) Decode(decoder *codec.SimpleDecoder) {
	m.MaxPacketTx = decoder.ReadU64()
	m.MaxPacketRx = decoder.ReadU64()
	m.MaxPacket = decoder.ReadU64()
	m.MaxBitTx = decoder.ReadU64()
	m.MaxBitRx = decoder.ReadU64()
	m.MaxBit = decoder.ReadU64()
}

func (m *UsageMeterMax) concurrentMerge(other *UsageMeterMax) {
	m.MaxPacketTx += other.MaxPacketTx
	m.MaxPacketRx += other.MaxPacketRx
	m.MaxPacket += other.MaxPacket
	m.MaxBitTx += other.MaxBitTx
	m.MaxBitRx += other.MaxBitRx
	m.MaxBit += other.MaxBit
}

func (m *UsageMeterMax) sequentialMerge(other *UsageMeterMax) {
	m.MaxPacketTx = maxU64(m.MaxPacketTx, other.MaxPacketTx)
	m.MaxPacketRx = maxU64(m.MaxPacketRx, other.MaxPacketRx)
	m.MaxPacket = maxU64(m.MaxPacket, other.MaxPacket)
	m.MaxBitTx = maxU64(m.MaxBitTx, other.MaxBitTx)
	m.MaxBitRx = maxU64(m.MaxBitRx, other.MaxBitRx)
	m.MaxBit = maxU64(m.MaxBit, other.MaxBit)
}
