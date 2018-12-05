package zerodoc

import (
	"strconv"
	"strings"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type ConsoleLogMeter struct {
	SumPacketTx           uint64        `db:"sum_packet_tx"`
	SumPacketRx           uint64        `db:"sum_packet_rx"`
	SumClosedFlowCount    uint64        `db:"sum_closed_flow_count"`
	SumClosedFlowDuration time.Duration `db:"sum_closed_flow_duration"`
}

func (m *ConsoleLogMeter) SortKey() uint64 {
	return m.SumPacketTx + m.SumPacketRx
}

func (m *ConsoleLogMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU64(m.SumPacketTx)
	encoder.WriteU64(m.SumPacketRx)
	encoder.WriteU64(m.SumClosedFlowCount)
	encoder.WriteU64(uint64(m.SumClosedFlowDuration))
}

func (m *ConsoleLogMeter) Decode(decoder *codec.SimpleDecoder) {
	m.SumPacketTx = decoder.ReadU64()
	m.SumPacketRx = decoder.ReadU64()
	m.SumClosedFlowCount = decoder.ReadU64()
	m.SumClosedFlowDuration = time.Duration(decoder.ReadU64())
}

func (m *ConsoleLogMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*ConsoleLogMeter); ok {
		m.SumPacketTx += pm.SumPacketTx
		m.SumPacketRx += pm.SumPacketRx
		m.SumClosedFlowCount += pm.SumClosedFlowCount
		m.SumClosedFlowDuration += pm.SumClosedFlowDuration
	}
}

func (m *ConsoleLogMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*ConsoleLogMeter); ok {
		m.SumPacketTx += pm.SumPacketTx
		m.SumPacketRx += pm.SumPacketRx
		m.SumClosedFlowCount += pm.SumClosedFlowCount
		m.SumClosedFlowDuration += pm.SumClosedFlowDuration
	}
}

func (m *ConsoleLogMeter) ToKVString() string {
	var buf strings.Builder
	buf.WriteString("sum_packet_tx=")
	buf.WriteString(strconv.FormatUint(m.SumPacketTx, 10))
	buf.WriteString("i,sum_packet_rx=")
	buf.WriteString(strconv.FormatUint(m.SumPacketRx, 10))
	buf.WriteString("i,sum_closed_flow_count=")
	buf.WriteString(strconv.FormatUint(m.SumClosedFlowCount, 10))
	buf.WriteString("i,sum_closed_flow_duration=")
	buf.WriteString(strconv.FormatInt(int64(m.SumClosedFlowDuration/time.Microsecond), 10))
	buf.WriteRune('i')
	return buf.String()
}
