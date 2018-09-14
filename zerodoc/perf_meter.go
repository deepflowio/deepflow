package zerodoc

import (
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type PerfMeter struct {
	PerfMeterSum
	PerfMeterMax
	PerfMeterMin
}

func (m *PerfMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*PerfMeter); ok {
		m.PerfMeterSum.concurrentMerge(&pm.PerfMeterSum)
		m.PerfMeterMax.concurrentMerge(&pm.PerfMeterMax)
		m.PerfMeterMin.concurrentMerge(&pm.PerfMeterMin)
	}
}

func (m *PerfMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*PerfMeter); ok {
		m.PerfMeterSum.sequentialMerge(&pm.PerfMeterSum)
		m.PerfMeterMax.sequentialMerge(&pm.PerfMeterMax)
		m.PerfMeterMin.sequentialMerge(&pm.PerfMeterMin)
	}
}

func (m *PerfMeter) ToMap() map[string]interface{} {
	pm := make(map[string]interface{})
	//perfMeterSum
	m.PerfMeterSum.ToMap(pm)

	//perfMeterMax
	m.PerfMeterMax.ToMap(pm)

	//perfMeterMin
	m.PerfMeterMin.ToMap(pm)
	return pm
}

type PerfMeterSum struct {
	SumFlowCount         uint64
	SumClosedFlowCount   uint64
	SumRetransFlowCount  uint64
	SumHalfOpenFlowCount uint64
	SumPacketTx          uint64
	SumPacketRx          uint64
	SumRetransCntTx      uint64
	SumRetransCntRx      uint64

	SumRTTSyn        time.Duration
	SumRTTAvg        time.Duration
	SumRTTSynFlow    uint64
	SumRTTAvgFlow    uint64
	SumRTTSynPerFlow uint64
	SumRTTAvgPerFlow uint64

	SumZeroWndCntTx uint64
	SumZeroWndCntRx uint64
}

func (m *PerfMeterSum) concurrentMerge(other *PerfMeterSum) {
	m.SumFlowCount += other.SumFlowCount
	m.SumClosedFlowCount += other.SumClosedFlowCount
	m.SumRetransFlowCount += other.SumRetransFlowCount
	m.SumHalfOpenFlowCount += other.SumHalfOpenFlowCount
	m.SumPacketTx += other.SumPacketTx
	m.SumPacketRx += other.SumPacketRx
	m.SumRetransCntTx += other.SumRetransCntTx
	m.SumRetransCntRx += other.SumRetransCntRx

	m.SumRTTSyn += other.SumRTTSyn
	m.SumRTTAvg += other.SumRTTAvg
	m.SumRTTSynFlow += other.SumRTTSynFlow
	m.SumRTTAvgFlow += other.SumRTTAvgFlow
	m.SumRTTSynPerFlow += other.SumRTTSynPerFlow
	m.SumRTTAvgPerFlow += other.SumRTTAvgPerFlow

	m.SumZeroWndCntTx += other.SumZeroWndCntTx
	m.SumZeroWndCntRx += other.SumZeroWndCntRx
}

func (m *PerfMeterSum) sequentialMerge(other *PerfMeterSum) {
	m.concurrentMerge(other)
}

func (m *PerfMeterSum) ToMap(mm map[string]interface{}) {
	mm["sum_flow_count"] = int64(m.SumFlowCount)
	mm["sum_closed_flow_count"] = int64(m.SumClosedFlowCount)
	mm["sum_retrans_flow_count"] = int64(m.SumRetransFlowCount)
	mm["sum_half_open_flow_count"] = int64(m.SumHalfOpenFlowCount)
	mm["sum_packet_tx"] = int64(m.SumPacketTx)
	mm["sum_packet_rx"] = int64(m.SumPacketRx)
	mm["sum_retrans_cnt_tx"] = int64(m.SumRetransCntTx)
	mm["sum_retrans_cnt_rx"] = int64(m.SumRetransCntRx)

	mm["sum_rtt_syn"] = int64(m.SumRTTSyn / time.Microsecond)
	mm["sum_rtt_avg"] = int64(m.SumRTTAvg / time.Microsecond)
	mm["sum_rtt_syn_flow"] = int64(m.SumRTTSynFlow)
	mm["sum_rtt_avg_flow"] = int64(m.SumRTTAvgFlow)
	if m.SumRTTSynFlow != 0 {
		mm["sum_rtt_syn_per_flow"] = int64(m.SumRTTSyn) / int64(m.SumRTTSynFlow)
	} else {
		mm["sum_rtt_syn_per_flow"] = 0
	}
	if m.SumRTTAvgFlow != 0 {
		mm["sum_rtt_avg_per_flow"] = int64(m.SumRTTAvg) / int64(m.SumRTTAvgFlow)
	} else {
		mm["sum_rtt_avg_per_flow"] = 0
	}

	mm["sum_zero_wnd_cnt_tx"] = int64(m.SumZeroWndCntTx)
	mm["sum_zero_wnd_cnt_rx"] = int64(m.SumZeroWndCntRx)
}

type PerfMeterMax struct {
	MaxRTTSyn time.Duration
	MaxRTTAvg time.Duration
}

func (m *PerfMeterMax) ToMap(mm map[string]interface{}) {
	mm["max_rtt_syn"] = int64(m.MaxRTTSyn / time.Microsecond)
	mm["max_rtt_avg"] = int64(m.MaxRTTAvg / time.Microsecond)
}

func (m *PerfMeterMax) concurrentMerge(other *PerfMeterMax) {
	m.MaxRTTSyn += other.MaxRTTSyn
	m.MaxRTTAvg += other.MaxRTTAvg
}

func (m *PerfMeterMax) sequentialMerge(other *PerfMeterMax) {
	m.MaxRTTSyn = maxDuration(m.MaxRTTSyn, other.MaxRTTSyn)
	m.MaxRTTAvg = maxDuration(m.MaxRTTAvg, other.MaxRTTAvg)
}

type PerfMeterMin struct {
	MinRTTSyn time.Duration
	MinRTTAvg time.Duration
}

func (m *PerfMeterMin) ToMap(mm map[string]interface{}) {
	mm["min_rtt_syn"] = int64(m.MinRTTSyn / time.Microsecond)
	mm["min_rtt_avg"] = int64(m.MinRTTAvg / time.Microsecond)
}

func (m *PerfMeterMin) concurrentMerge(other *PerfMeterMin) {
	m.MinRTTSyn += other.MinRTTSyn
	m.MinRTTAvg += other.MinRTTAvg
}

func (m *PerfMeterMin) sequentialMerge(other *PerfMeterMin) {
	m.MinRTTSyn = minDuration(m.MinRTTSyn, other.MinRTTSyn)
	m.MinRTTAvg = minDuration(m.MinRTTAvg, other.MinRTTAvg)
}
