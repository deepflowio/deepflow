package zerodoc

import (
	"strconv"
	"strings"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type ConsoleLogMeter struct {
	SumPacketTx           uint64
	SumPacketRx           uint64
	SumClosedFlowCount    uint64
	SumClosedFlowDuration time.Duration
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
