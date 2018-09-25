package zerodoc

import (
	"strconv"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type FlowMeter struct {
	SumFlowCount       uint64
	SumNewFlowCount    uint64
	SumClosedFlowCount uint64

	MaxFlowCount    uint64
	MaxNewFlowCount uint64
}

func (m *FlowMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*FlowMeter); ok {
		m.SumFlowCount += pm.SumFlowCount
		m.SumNewFlowCount += pm.SumNewFlowCount
		m.SumClosedFlowCount += pm.SumClosedFlowCount

		m.MaxFlowCount += pm.MaxFlowCount
		m.MaxNewFlowCount += pm.MaxNewFlowCount
	}
}

func (m *FlowMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*FlowMeter); ok {
		m.SumFlowCount += pm.SumFlowCount
		m.SumNewFlowCount += pm.SumNewFlowCount
		m.SumClosedFlowCount += pm.SumClosedFlowCount

		m.MaxFlowCount = maxU64(m.MaxFlowCount, pm.MaxFlowCount)
		m.MaxNewFlowCount = maxU64(m.MaxNewFlowCount, pm.MaxNewFlowCount)
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

	buf.WriteString("i,max_flow_count=")
	buf.WriteString(strconv.FormatUint(m.MaxFlowCount, 10))
	buf.WriteString("i,max_new_flow_count=")
	buf.WriteString(strconv.FormatUint(m.MaxNewFlowCount, 10))
	buf.WriteRune('i')

	return buf.String()
}
