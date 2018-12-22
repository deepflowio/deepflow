package zerodoc

import (
	"strconv"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type FlowMeter struct {
	SumFlowCount       uint64 `db:"sum_flow_count"`
	SumNewFlowCount    uint64 `db:"sum_new_flow_count"`
	SumClosedFlowCount uint64 `db:"sum_closed_flow_count"`
	SumPacketTx        uint64 `db:"sum_packet_tx"`
	SumPacketRx        uint64 `db:"sum_packet_rx"`
	SumBitTx           uint64 `db:"sum_bit_tx"`
	SumBitRx           uint64 `db:"sum_bit_rx"`
}

func (m *FlowMeter) SortKey() uint64 {
	return m.SumPacketTx + m.SumPacketRx
}

func (m *FlowMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU64(m.SumFlowCount)
	encoder.WriteU64(m.SumNewFlowCount)
	encoder.WriteU64(m.SumClosedFlowCount)
	encoder.WriteU64(m.SumPacketTx)
	encoder.WriteU64(m.SumPacketRx)
	encoder.WriteU64(m.SumBitTx)
	encoder.WriteU64(m.SumBitRx)
}

func (m *FlowMeter) Decode(decoder *codec.SimpleDecoder) {
	m.SumFlowCount = decoder.ReadU64()
	m.SumNewFlowCount = decoder.ReadU64()
	m.SumClosedFlowCount = decoder.ReadU64()
	m.SumPacketTx = decoder.ReadU64()
	m.SumPacketRx = decoder.ReadU64()
	m.SumBitTx = decoder.ReadU64()
	m.SumBitRx = decoder.ReadU64()
}

func (m *FlowMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*FlowMeter); ok {
		m.SumFlowCount += pm.SumFlowCount
		m.SumNewFlowCount += pm.SumNewFlowCount
		m.SumClosedFlowCount += pm.SumClosedFlowCount
		m.SumPacketTx += pm.SumPacketTx
		m.SumPacketRx += pm.SumPacketRx
		m.SumBitTx += pm.SumBitTx
		m.SumBitRx += pm.SumBitRx
	}
}

func (m *FlowMeter) SequentialMerge(other app.Meter) { // other为后一个时间的统计量
	if pm, ok := other.(*FlowMeter); ok {
		m.SumFlowCount = m.SumClosedFlowCount + pm.SumFlowCount
		m.SumNewFlowCount += pm.SumNewFlowCount
		m.SumClosedFlowCount += pm.SumClosedFlowCount
		m.SumPacketTx += pm.SumPacketTx
		m.SumPacketRx += pm.SumPacketRx
		m.SumBitTx += pm.SumBitTx
		m.SumBitRx += pm.SumBitRx
	}
}

func (m *FlowMeter) ToKVString() string {
	var buf strings.Builder

	buf.WriteString("sum_flow_count=")
	buf.WriteString(strconv.FormatUint(m.SumFlowCount, 10))
	buf.WriteString("i,sum_new_flow_count=")
	buf.WriteString(strconv.FormatUint(m.SumNewFlowCount, 10))
	buf.WriteString("i,sum_closed_flow_count=")
	buf.WriteString(strconv.FormatUint(m.SumClosedFlowCount, 10))
	buf.WriteString("i,sum_packet_tx=")
	buf.WriteString(strconv.FormatUint(m.SumPacketTx, 10))
	buf.WriteString("i,sum_packet_rx=")
	buf.WriteString(strconv.FormatUint(m.SumPacketRx, 10))
	buf.WriteString("i,sum_packet=")
	buf.WriteString(strconv.FormatUint(m.SumPacketTx+m.SumBitRx, 10))
	buf.WriteString("i,sum_bit_tx=")
	buf.WriteString(strconv.FormatUint(m.SumBitTx, 10))
	buf.WriteString("i,sum_bit_rx=")
	buf.WriteString(strconv.FormatUint(m.SumBitRx, 10))
	buf.WriteString("i,sum_bit=")
	buf.WriteString(strconv.FormatUint(m.SumBitTx+m.SumBitRx, 10))
	buf.WriteRune('i')

	return buf.String()
}
