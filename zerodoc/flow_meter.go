package zerodoc

import "gitlab.x.lan/yunshan/droplet-libs/app"

type FlowMeter struct {
	SumFlowCount       uint64
	SumNewFlowCount    uint64
	SumClosedFlowCount uint64

	SumClosedFlowCountL0S1S  uint64
	SumClosedFlowCountL1S5S  uint64
	SumClosedFlowCountL5S10S uint64
	SumClosedFlowCountL10S1M uint64
	SumClosedFlowCountL1M1H  uint64
	SumClosedFlowCountL1H    uint64

	SumClosedFlowCountE0K10K   uint64
	SumClosedFlowCountE10K100K uint64
	SumClosedFlowCountE100K1M  uint64
	SumClosedFlowCountE1M100M  uint64
	SumClosedFlowCountE100M1G  uint64
	SumClosedFlowCountE1G      uint64

	SumClosedFlowCountTRst       uint64
	SumClosedFlowCountTHalfOpen  uint64
	SumClosedFlowCountTHalfClose uint64

	MaxFlowCount    uint64
	MaxNewFlowCount uint64
}

func (m *FlowMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*FlowMeter); ok {
		m.SumFlowCount += pm.SumFlowCount
		m.SumClosedFlowCount += pm.SumNewFlowCount
		m.SumClosedFlowCount += pm.SumClosedFlowCount

		m.SumClosedFlowCountL0S1S += pm.SumClosedFlowCountL0S1S
		m.SumClosedFlowCountL1S5S += pm.SumClosedFlowCountL1S5S
		m.SumClosedFlowCountL5S10S += pm.SumClosedFlowCountL5S10S
		m.SumClosedFlowCountL10S1M += pm.SumClosedFlowCountL10S1M
		m.SumClosedFlowCountL1M1H += pm.SumClosedFlowCountL1M1H
		m.SumClosedFlowCountL1H += pm.SumClosedFlowCountL1H

		m.SumClosedFlowCountE0K10K += pm.SumClosedFlowCountE0K10K
		m.SumClosedFlowCountE10K100K += pm.SumClosedFlowCountE10K100K
		m.SumClosedFlowCountE100K1M += pm.SumClosedFlowCountE100K1M
		m.SumClosedFlowCountE1M100M += pm.SumClosedFlowCountE1M100M
		m.SumClosedFlowCountE100M1G += pm.SumClosedFlowCountE100M1G
		m.SumClosedFlowCountE1G += pm.SumClosedFlowCountE1G

		m.SumClosedFlowCountTRst += pm.SumClosedFlowCountTRst
		m.SumClosedFlowCountTHalfOpen += pm.SumClosedFlowCountTHalfOpen
		m.SumClosedFlowCountTHalfClose += pm.SumClosedFlowCountTHalfClose

		m.MaxFlowCount += pm.MaxFlowCount
		m.MaxNewFlowCount += pm.MaxNewFlowCount
	}
}

func (m *FlowMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*FlowMeter); ok {
		m.SumFlowCount += pm.SumFlowCount
		m.SumNewFlowCount += pm.SumNewFlowCount
		m.SumClosedFlowCount += pm.SumClosedFlowCount

		m.SumClosedFlowCountL0S1S += pm.SumClosedFlowCountL0S1S
		m.SumClosedFlowCountL1S5S += pm.SumClosedFlowCountL1S5S
		m.SumClosedFlowCountL5S10S += pm.SumClosedFlowCountL5S10S
		m.SumClosedFlowCountL10S1M += pm.SumClosedFlowCountL10S1M
		m.SumClosedFlowCountL1M1H += pm.SumClosedFlowCountL1M1H
		m.SumClosedFlowCountL1H += pm.SumClosedFlowCountL1H

		m.SumClosedFlowCountE0K10K += pm.SumClosedFlowCountE0K10K
		m.SumClosedFlowCountE10K100K += pm.SumClosedFlowCountE10K100K
		m.SumClosedFlowCountE100K1M += pm.SumClosedFlowCountE100K1M
		m.SumClosedFlowCountE1M100M += pm.SumClosedFlowCountE1M100M
		m.SumClosedFlowCountE100M1G += pm.SumClosedFlowCountE100M1G
		m.SumClosedFlowCountE1G += pm.SumClosedFlowCountE1G

		m.SumClosedFlowCountTRst += pm.SumClosedFlowCountTRst
		m.SumClosedFlowCountTHalfOpen += pm.SumClosedFlowCountTHalfOpen
		m.SumClosedFlowCountTHalfClose += pm.SumClosedFlowCountTHalfClose

		m.MaxFlowCount = maxU64(m.MaxFlowCount, pm.MaxFlowCount)
		m.MaxNewFlowCount = maxU64(m.MaxNewFlowCount, pm.MaxNewFlowCount)
	}
}

func (m *FlowMeter) ToMap() map[string]interface{} {
	pm := make(map[string]interface{})
	pm["sum_flow_count"] = int64(m.SumFlowCount)
	pm["sum_new_flow_count"] = int64(m.SumNewFlowCount)
	pm["sum_closed_flow_count"] = int64(m.SumClosedFlowCount)

	pm["sum_closed_flow_count_l_0s1s"] = int64(m.SumClosedFlowCountL0S1S)
	pm["sum_closed_flow_count_l_1s5s"] = int64(m.SumClosedFlowCountL1S5S)
	pm["sum_closed_flow_count_l_5s10s"] = int64(m.SumClosedFlowCountL5S10S)
	pm["sum_closed_flow_count_l_10s1m"] = int64(m.SumClosedFlowCountL10S1M)
	pm["sum_closed_flow_count_l_1m1h"] = int64(m.SumClosedFlowCountL1M1H)
	pm["sum_closed_flow_count_l_1h"] = int64(m.SumClosedFlowCountL1H)

	pm["sum_closed_flow_count_e_0k10k"] = int64(m.SumClosedFlowCountE0K10K)
	pm["sum_closed_flow_count_e_10k100k"] = int64(m.SumClosedFlowCountE10K100K)
	pm["sum_closed_flow_count_e_100k1m"] = int64(m.SumClosedFlowCountE100K1M)
	pm["sum_closed_flow_count_e_1m100m"] = int64(m.SumClosedFlowCountE1M100M)
	pm["sum_closed_flow_count_e_100m1g"] = int64(m.SumClosedFlowCountE100M1G)
	pm["sum_closed_flow_count_e_1g"] = int64(m.SumClosedFlowCountE1G)

	pm["sum_closed_flow_count_t_rst"] = int64(m.SumClosedFlowCountTRst)
	pm["sum_closed_flow_count_t_half_open"] = int64(m.SumClosedFlowCountTHalfOpen)
	pm["sum_closed_flow_count_t_half_close"] = int64(m.SumClosedFlowCountTHalfClose)

	pm["max_flow_count"] = int64(m.MaxFlowCount)
	pm["max_new_flow_count"] = int64(m.MaxNewFlowCount)

	return pm
}
