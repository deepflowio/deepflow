package zerodoc

import (
	"strconv"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type UsageMeter struct {
	UsageMeterSum
	UsageMeterMax
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
	var buf strings.Builder

	// sum
	sum := m.UsageMeterSum
	buf.WriteString("sum_packet_tx=")
	buf.WriteString(strconv.FormatUint(sum.SumPacketTx, 10))
	buf.WriteString("i,sum_packet_rx=")
	buf.WriteString(strconv.FormatUint(sum.SumPacketRx, 10))
	buf.WriteString("i,sum_packet=")
	buf.WriteString(strconv.FormatUint(sum.SumPacket, 10))
	buf.WriteString("i,sum_bit_tx=")
	buf.WriteString(strconv.FormatUint(sum.SumBitTx, 10))
	buf.WriteString("i,sum_bit_rx=")
	buf.WriteString(strconv.FormatUint(sum.SumBitRx, 10))
	buf.WriteString("i,sum_bit=")
	buf.WriteString(strconv.FormatUint(sum.SumBit, 10))

	// max
	max := m.UsageMeterMax
	buf.WriteString("i,max_packet_tx=")
	buf.WriteString(strconv.FormatUint(max.MaxPacketTx, 10))
	buf.WriteString("i,max_packet_rx=")
	buf.WriteString(strconv.FormatUint(max.MaxPacketRx, 10))
	buf.WriteString("i,max_packet=")
	buf.WriteString(strconv.FormatUint(max.MaxPacket, 10))
	buf.WriteString("i,max_bit_tx=")
	buf.WriteString(strconv.FormatUint(max.MaxBitTx, 10))
	buf.WriteString("i,max_bit_rx=")
	buf.WriteString(strconv.FormatUint(max.MaxBitRx, 10))
	buf.WriteString("i,max_bit=")
	buf.WriteString(strconv.FormatUint(max.MaxBit, 10))
	buf.WriteRune('i')

	return buf.String()
}

type UsageMeterSum struct {
	SumPacketTx uint64 `db:"sum_packet_tx"`
	SumPacketRx uint64 `db:"sum_packet_rx"`
	SumPacket   uint64 `db:"sum_packet"`
	SumBitTx    uint64 `db:"sum_bit_tx"`
	SumBitRx    uint64 `db:"sum_bit_rx"`
	SumBit      uint64 `db:"sum_bit"`
}

func (m *UsageMeterSum) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU64(m.SumPacketTx)
	encoder.WriteU64(m.SumPacketRx)
	encoder.WriteU64(m.SumPacket)
	encoder.WriteU64(m.SumBitTx)
	encoder.WriteU64(m.SumBitRx)
	encoder.WriteU64(m.SumBit)
}

func (m *UsageMeterSum) Decode(decoder *codec.SimpleDecoder) {
	m.SumPacketTx = decoder.ReadU64()
	m.SumPacketRx = decoder.ReadU64()
	m.SumPacket = decoder.ReadU64()
	m.SumBitTx = decoder.ReadU64()
	m.SumBitRx = decoder.ReadU64()
	m.SumBit = decoder.ReadU64()
}

func (m *UsageMeterSum) concurrentMerge(other *UsageMeterSum) {
	m.SumPacketTx += other.SumPacketTx
	m.SumPacketRx += other.SumPacketRx
	m.SumPacket += other.SumPacket
	m.SumBitTx += other.SumBitTx
	m.SumBitRx += other.SumBitRx
	m.SumBit += other.SumBit
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
