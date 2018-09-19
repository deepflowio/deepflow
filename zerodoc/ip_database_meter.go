package zerodoc

import (
	"strconv"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type IPDatabaseMeter struct {
	SumBit             uint64
	SumClosedFlowCount uint64
}

func (m *IPDatabaseMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*IPDatabaseMeter); ok {
		m.SumBit += pm.SumBit
		m.SumClosedFlowCount += pm.SumClosedFlowCount
	}
}

func (m *IPDatabaseMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*IPDatabaseMeter); ok {
		m.SumBit += pm.SumBit
		m.SumClosedFlowCount += pm.SumClosedFlowCount
	}
}

func (m *IPDatabaseMeter) ToKVString() string {
	var buf strings.Builder
	buf.WriteString("sum_bit=")
	buf.WriteString(strconv.FormatUint(m.SumBit, 10))
	buf.WriteString("i,sum_closed_flow_count=")
	buf.WriteString(strconv.FormatUint(m.SumClosedFlowCount, 10))
	buf.WriteRune('i')
	return buf.String()
}
