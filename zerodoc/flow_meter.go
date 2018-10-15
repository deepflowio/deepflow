package zerodoc

import (
	"strconv"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type FlowMeter struct {
	SumFlowCount       uint64 `db:"sum_flow_count"`
	SumNewFlowCount    uint64 `db:"sum_new_flow_count"`
	SumClosedFlowCount uint64 `db:"sum_closed_flow_count"`
	SumPacketTx        uint64 `db:"sum_packet_tx"`
	SumPacketRx        uint64 `db:"sum_packet_rx"`
	SumPacket          uint64 `db:"sum_packet"`
	SumBitTx           uint64 `db:"sum_bit_tx"`
	SumBitRx           uint64 `db:"sum_bit_rx"`
	SumBit             uint64 `db:"sum_bit"`
}

func (m *FlowMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*FlowMeter); ok {
		m.SumFlowCount += pm.SumFlowCount
		m.SumNewFlowCount += pm.SumNewFlowCount
		m.SumClosedFlowCount += pm.SumClosedFlowCount
		m.SumPacketTx += pm.SumPacketTx
		m.SumPacketRx += pm.SumPacketRx
		m.SumPacket += pm.SumPacket
		m.SumBitTx += pm.SumBitTx
		m.SumBitRx += pm.SumBitRx
		m.SumBit += pm.SumBit
	}
}

func (m *FlowMeter) SequentialMerge(other app.Meter) { // other为后一个时间的统计量
	if pm, ok := other.(*FlowMeter); ok {
		m.SumFlowCount = m.SumClosedFlowCount + pm.SumFlowCount
		m.SumNewFlowCount += pm.SumNewFlowCount
		m.SumClosedFlowCount += pm.SumClosedFlowCount
		m.SumPacketTx += pm.SumPacketTx
		m.SumPacketRx += pm.SumPacketRx
		m.SumPacket += pm.SumPacket
		m.SumBitTx += pm.SumBitTx
		m.SumBitRx += pm.SumBitRx
		m.SumBit += pm.SumBit
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
	buf.WriteString(strconv.FormatUint(m.SumPacket, 10))
	buf.WriteString("i,sum_bit_tx=")
	buf.WriteString(strconv.FormatUint(m.SumBitTx, 10))
	buf.WriteString("i,sum_bit_rx=")
	buf.WriteString(strconv.FormatUint(m.SumBitRx, 10))
	buf.WriteString("i,sum_bit=")
	buf.WriteString(strconv.FormatUint(m.SumBit, 10))
	buf.WriteRune('i')

	return buf.String()
}
