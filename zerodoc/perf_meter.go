package zerodoc

import (
	"strconv"
	"strings"
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

func (m *PerfMeter) ToKVString() string {
	var buf strings.Builder

	// sum
	sum := m.PerfMeterSum
	buf.WriteString("sum_flow_count=")
	buf.WriteString(strconv.FormatUint(sum.SumFlowCount, 10))
	buf.WriteString("i,sum_closed_flow_count=")
	buf.WriteString(strconv.FormatUint(sum.SumClosedFlowCount, 10))
	buf.WriteString("i,sum_retrans_flow_count=")
	buf.WriteString(strconv.FormatUint(sum.SumRetransFlowCount, 10))
	buf.WriteString("i,sum_half_open_flow_count=")
	buf.WriteString(strconv.FormatUint(sum.SumHalfOpenFlowCount, 10))
	buf.WriteString("i,sum_packet_tx=")
	buf.WriteString(strconv.FormatUint(sum.SumPacketTx, 10))
	buf.WriteString("i,sum_packet_rx=")
	buf.WriteString(strconv.FormatUint(sum.SumPacketRx, 10))
	buf.WriteString("i,sum_retrans_cnt_tx=")
	buf.WriteString(strconv.FormatUint(sum.SumRetransCntTx, 10))
	buf.WriteString("i,sum_retrans_cnt_rx=")
	buf.WriteString(strconv.FormatUint(sum.SumRetransCntRx, 10))

	buf.WriteString("i,sum_rtt_syn=")
	buf.WriteString(strconv.FormatInt(int64(sum.SumRTTSyn/time.Microsecond), 10))
	buf.WriteString("i,sum_rtt_avg=")
	buf.WriteString(strconv.FormatInt(int64(sum.SumRTTAvg/time.Microsecond), 10))
	buf.WriteString("i,sum_rtt_syn_flow=")
	buf.WriteString(strconv.FormatUint(sum.SumRTTSynFlow, 10))
	buf.WriteString("i,sum_rtt_avg_flow=")
	buf.WriteString(strconv.FormatUint(sum.SumRTTAvgFlow, 10))
	buf.WriteString("i,sum_zero_wnd_cnt_tx=")
	buf.WriteString(strconv.FormatUint(sum.SumZeroWndCntTx, 10))
	buf.WriteString("i,sum_zero_wnd_cnt_rx=")
	buf.WriteString(strconv.FormatUint(sum.SumZeroWndCntRx, 10))

	// max
	max := m.PerfMeterMax
	buf.WriteString("i,max_rtt_syn=")
	buf.WriteString(strconv.FormatInt(int64(max.MaxRTTSyn/time.Microsecond), 10))
	buf.WriteString("i,max_rtt_avg=")
	buf.WriteString(strconv.FormatInt(int64(max.MaxRTTAvg/time.Microsecond), 10))

	// min
	min := m.PerfMeterMin
	buf.WriteString("i,min_rtt_syn=")
	buf.WriteString(strconv.FormatInt(int64(min.MinRTTSyn/time.Microsecond), 10))
	buf.WriteString("i,min_rtt_avg=")
	buf.WriteString(strconv.FormatInt(int64(min.MinRTTAvg/time.Microsecond), 10))
	buf.WriteRune('i')

	return buf.String()
}

type PerfMeterSum struct {
	SumFlowCount         uint64 `db:"sum_flow_count"`
	SumClosedFlowCount   uint64 `db:"sum_closed_flow_count"`
	SumRetransFlowCount  uint64 `db:"sum_retrans_flow_count"`
	SumHalfOpenFlowCount uint64 `db:"sum_half_open_flow_count"`
	SumPacketTx          uint64 `db:"sum_packet_tx"`
	SumPacketRx          uint64 `db:"sum_packet_rx"`
	SumRetransCntTx      uint64 `db:"sum_retrans_cnt_tx"`
	SumRetransCntRx      uint64 `db:"sum_retrans_cnt_rx"`

	SumRTTSyn     time.Duration `db:"sum_rtt_syn"`
	SumRTTAvg     time.Duration `db:"sum_rtt_avg"`
	SumRTTSynFlow uint64        `db:"sum_rtt_syn_flow"`
	SumRTTAvgFlow uint64        `db:"sum_rtt_avg_flow"`

	SumZeroWndCntTx uint64 `db:"sum_zero_wnd_cnt_tx"`
	SumZeroWndCntRx uint64 `db:"sum_zero_wnd_cnt_rx"`
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

	m.SumZeroWndCntTx += other.SumZeroWndCntTx
	m.SumZeroWndCntRx += other.SumZeroWndCntRx
}

func (m *PerfMeterSum) sequentialMerge(other *PerfMeterSum) { // other为后一个时间的统计量
	m.SumFlowCount = m.SumClosedFlowCount + other.SumFlowCount
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

	m.SumZeroWndCntTx += other.SumZeroWndCntTx
	m.SumZeroWndCntRx += other.SumZeroWndCntRx
}

type PerfMeterMax struct {
	MaxRTTSyn time.Duration `db:"max_rtt_syn"`
	MaxRTTAvg time.Duration `db:"max_rtt_avg"`
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
	MinRTTSyn time.Duration `db:"min_rtt_syn"`
	MinRTTAvg time.Duration `db:"min_rtt_avg"`
}

func (m *PerfMeterMin) concurrentMerge(other *PerfMeterMin) {
	m.MinRTTSyn += other.MinRTTSyn
	m.MinRTTAvg += other.MinRTTAvg
}

func (m *PerfMeterMin) sequentialMerge(other *PerfMeterMin) {
	m.MinRTTSyn = minDuration(m.MinRTTSyn, other.MinRTTSyn)
	m.MinRTTAvg = minDuration(m.MinRTTAvg, other.MinRTTAvg)
}
