package zerodoc

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type ConsoleLogMeter struct {
	SumPacketTx           uint64 `db:"sum_packet_tx"`
	SumPacketRx           uint64 `db:"sum_packet_rx"`
	SumClosedFlowCount    uint64 `db:"sum_closed_flow_count"`
	SumClosedFlowDuration uint64 `db:"sum_closed_flow_duration"` // ms
}

func (m *ConsoleLogMeter) SortKey() uint64 {
	return m.SumPacketTx + m.SumPacketRx
}

func (m *ConsoleLogMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.SumPacketTx)
	encoder.WriteVarintU64(m.SumPacketRx)
	encoder.WriteVarintU64(m.SumClosedFlowCount)
	encoder.WriteVarintU64(m.SumClosedFlowDuration)
}

func (m *ConsoleLogMeter) Decode(decoder *codec.SimpleDecoder) {
	m.SumPacketTx = decoder.ReadVarintU64()
	m.SumPacketRx = decoder.ReadVarintU64()
	m.SumClosedFlowCount = decoder.ReadVarintU64()
	m.SumClosedFlowDuration = decoder.ReadVarintU64()
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
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *ConsoleLogMeter) MarshalTo(b []byte) int {
	offset := 0

	offset += copy(b[offset:], "sum_packet_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumPacketTx, 10))
	offset += copy(b[offset:], "i,sum_packet_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumPacketRx, 10))
	offset += copy(b[offset:], "i,sum_closed_flow_count=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumClosedFlowCount, 10))
	offset += copy(b[offset:], "i,sum_closed_flow_duration=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumClosedFlowDuration*1000, 10)) // us
	b[offset] = 'i'
	offset++

	return offset
}

func (m *ConsoleLogMeter) Fill(isTag []bool, names []string, values []interface{}) {
	for i, name := range names {
		if isTag[i] || values[i] == nil {
			continue
		}
		switch name {
		case "sum_packet_tx":
			m.SumPacketTx = uint64(values[i].(int64))
		case "sum_packet_rx":
			m.SumPacketRx = uint64(values[i].(int64))
		case "sum_closed_flow_count":
			m.SumClosedFlowCount = uint64(values[i].(int64))
		case "sum_closed_flow_duration":
			m.SumClosedFlowDuration = uint64(values[i].(int64) / 1000)
		}
	}
}
