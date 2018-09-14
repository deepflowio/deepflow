package zerodoc

import "gitlab.x.lan/yunshan/droplet-libs/app"

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

func (m *IPDatabaseMeter) ToMap() map[string]interface{} {
	pm := make(map[string]interface{})
	pm["sum_bit"] = int64(m.SumBit)
	pm["sum_closed_flow_count"] = int64(m.SumClosedFlowCount)
	return pm
}
