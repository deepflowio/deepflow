package zerodoc

import (
	"strconv"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type FPSMeter struct {
	SumFlowCount       uint64
	SumNewFlowCount    uint64
	SumClosedFlowCount uint64

	MaxFlowCount    uint64
	MaxNewFlowCount uint64
}

func (m *FPSMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*FPSMeter); ok {
		m.SumFlowCount += pm.SumFlowCount
		m.SumNewFlowCount += pm.SumNewFlowCount
		m.SumClosedFlowCount += pm.SumClosedFlowCount

		m.MaxFlowCount += pm.MaxFlowCount
		m.MaxNewFlowCount += pm.MaxNewFlowCount
	}
}

func (m *FPSMeter) SequentialMerge(other app.Meter) { // other为后一个时间的统计量
	if pm, ok := other.(*FPSMeter); ok {
		m.SumFlowCount = m.SumClosedFlowCount + pm.SumFlowCount
		m.SumNewFlowCount += pm.SumNewFlowCount
		m.SumClosedFlowCount += pm.SumClosedFlowCount

		m.MaxFlowCount = maxU64(m.MaxFlowCount, pm.MaxFlowCount)
		m.MaxNewFlowCount = maxU64(m.MaxNewFlowCount, pm.MaxNewFlowCount)
	}
}

func (m *FPSMeter) ToKVString() string {
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
