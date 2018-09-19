package zerodoc

import (
	"strconv"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type UsageMeter struct {
	UsageMeterSum
	UsageMeterMax
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
	SumPacketTx uint64
	SumPacketRx uint64
	SumPacket   uint64
	SumBitTx    uint64
	SumBitRx    uint64
	SumBit      uint64
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
	MaxPacketTx uint64
	MaxPacketRx uint64
	MaxPacket   uint64
	MaxBitTx    uint64
	MaxBitRx    uint64
	MaxBit      uint64
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
