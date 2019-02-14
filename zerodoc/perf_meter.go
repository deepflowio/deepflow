package zerodoc

import (
	"strconv"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type PerfMeter struct {
	PerfMeterSum
	PerfMeterMax
	PerfMeterMin
}

func (m *PerfMeter) SortKey() uint64 {
	return m.PerfMeterSum.SumPacketTx + m.PerfMeterSum.SumPacketRx
}

func (m *PerfMeter) Encode(encoder *codec.SimpleEncoder) {
	m.PerfMeterSum.Encode(encoder)
	m.PerfMeterMax.Encode(encoder)
	m.PerfMeterMin.Encode(encoder)
}

func (m *PerfMeter) Decode(decoder *codec.SimpleDecoder) {
	m.PerfMeterSum.Decode(decoder)
	m.PerfMeterMax.Decode(decoder)
	m.PerfMeterMin.Decode(decoder)
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
	buffer := make([]byte, app.MAX_DOC_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *PerfMeter) MarshalTo(b []byte) int {
	offset := 0

	// sum
	sum := m.PerfMeterSum
	offset += copy(b[offset:], "sum_flow_count=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumFlowCount, 10))
	offset += copy(b[offset:], "i,sum_closed_flow_count=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumClosedFlowCount, 10))
	offset += copy(b[offset:], "i,sum_retrans_flow_count=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumRetransFlowCount, 10))
	offset += copy(b[offset:], "i,sum_half_open_flow_count=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumHalfOpenFlowCount, 10))
	offset += copy(b[offset:], "i,sum_packet_tx=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumPacketTx, 10))
	offset += copy(b[offset:], "i,sum_packet_rx=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumPacketRx, 10))
	offset += copy(b[offset:], "i,sum_bit_tx=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumBitTx, 10))
	offset += copy(b[offset:], "i,sum_bit_rx=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumBitRx, 10))
	offset += copy(b[offset:], "i,sum_bit=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumBitTx+sum.SumBitRx, 10))
	offset += copy(b[offset:], "i,sum_retrans_cnt_tx=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumRetransCntTx, 10))
	offset += copy(b[offset:], "i,sum_retrans_cnt_rx=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumRetransCntRx, 10))

	offset += copy(b[offset:], "i,sum_rtt_syn=")
	offset += copy(b[offset:], strconv.FormatInt(int64(sum.SumRTTSyn/time.Microsecond), 10))
	offset += copy(b[offset:], "i,sum_rtt_avg=")
	offset += copy(b[offset:], strconv.FormatInt(int64(sum.SumRTTAvg/time.Microsecond), 10))
	offset += copy(b[offset:], "i,sum_art_avg=")
	offset += copy(b[offset:], strconv.FormatInt(int64(sum.SumARTAvg/time.Microsecond), 10))
	offset += copy(b[offset:], "i,sum_rtt_syn_flow=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumRTTSynFlow, 10))
	offset += copy(b[offset:], "i,sum_rtt_avg_flow=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumRTTAvgFlow, 10))
	offset += copy(b[offset:], "i,sum_art_avg_flow=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumARTAvgFlow, 10))
	offset += copy(b[offset:], "i,sum_zero_wnd_cnt_tx=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumZeroWndCntTx, 10))
	offset += copy(b[offset:], "i,sum_zero_wnd_cnt_rx=")
	offset += copy(b[offset:], strconv.FormatUint(sum.SumZeroWndCntRx, 10))

	// max
	max := m.PerfMeterMax
	offset += copy(b[offset:], "i,max_rtt_syn=")
	offset += copy(b[offset:], strconv.FormatInt(int64(max.MaxRTTSyn/time.Microsecond), 10))
	offset += copy(b[offset:], "i,max_rtt_avg=")
	offset += copy(b[offset:], strconv.FormatInt(int64(max.MaxRTTAvg/time.Microsecond), 10))
	offset += copy(b[offset:], "i,max_art_avg=")
	offset += copy(b[offset:], strconv.FormatInt(int64(max.MaxARTAvg/time.Microsecond), 10))

	// min
	min := m.PerfMeterMin
	offset += copy(b[offset:], "i,min_rtt_syn=")
	offset += copy(b[offset:], strconv.FormatInt(int64(min.MinRTTSyn/time.Microsecond), 10))
	offset += copy(b[offset:], "i,min_rtt_avg=")
	offset += copy(b[offset:], strconv.FormatInt(int64(min.MinRTTAvg/time.Microsecond), 10))
	offset += copy(b[offset:], "i,min_art_avg=")
	offset += copy(b[offset:], strconv.FormatInt(int64(min.MinARTAvg/time.Microsecond), 10))
	b[offset] = 'i'
	offset++

	return offset
}

type PerfMeterSum struct {
	SumFlowCount         uint64 `db:"sum_flow_count"`
	SumClosedFlowCount   uint64 `db:"sum_closed_flow_count"`
	SumRetransFlowCount  uint64 `db:"sum_retrans_flow_count"`
	SumHalfOpenFlowCount uint64 `db:"sum_half_open_flow_count"`
	SumPacketTx          uint64 `db:"sum_packet_tx"`
	SumPacketRx          uint64 `db:"sum_packet_rx"`
	SumBitTx             uint64 `db:"sum_bit_tx"`
	SumBitRx             uint64 `db:"sum_bit_rx"`
	SumRetransCntTx      uint64 `db:"sum_retrans_cnt_tx"`
	SumRetransCntRx      uint64 `db:"sum_retrans_cnt_rx"`

	SumRTTSyn     time.Duration `db:"sum_rtt_syn"`
	SumRTTAvg     time.Duration `db:"sum_rtt_avg"`
	SumARTAvg     time.Duration `db:"sum_art_avg"`
	SumRTTSynFlow uint64        `db:"sum_rtt_syn_flow"`
	SumRTTAvgFlow uint64        `db:"sum_rtt_avg_flow"`
	SumARTAvgFlow uint64        `db:"sum_art_avg_flow"`

	SumZeroWndCntTx uint64 `db:"sum_zero_wnd_cnt_tx"`
	SumZeroWndCntRx uint64 `db:"sum_zero_wnd_cnt_rx"`
}

func (m *PerfMeterSum) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.SumFlowCount)
	encoder.WriteVarintU64(m.SumClosedFlowCount)
	encoder.WriteVarintU64(m.SumRetransFlowCount)
	encoder.WriteVarintU64(m.SumHalfOpenFlowCount)
	encoder.WriteVarintU64(m.SumPacketTx)
	encoder.WriteVarintU64(m.SumPacketRx)
	encoder.WriteVarintU64(m.SumBitTx)
	encoder.WriteVarintU64(m.SumBitRx)
	encoder.WriteVarintU64(m.SumRetransCntTx)
	encoder.WriteVarintU64(m.SumRetransCntRx)

	encoder.WriteVarintU64(uint64(m.SumRTTSyn))
	encoder.WriteVarintU64(uint64(m.SumRTTAvg))
	encoder.WriteVarintU64(uint64(m.SumARTAvg))
	encoder.WriteVarintU64(m.SumRTTSynFlow)
	encoder.WriteVarintU64(m.SumRTTAvgFlow)
	encoder.WriteVarintU64(m.SumARTAvgFlow)

	encoder.WriteVarintU64(m.SumZeroWndCntTx)
	encoder.WriteVarintU64(m.SumZeroWndCntRx)
}

func (m *PerfMeterSum) Decode(decoder *codec.SimpleDecoder) {
	m.SumFlowCount = decoder.ReadVarintU64()
	m.SumClosedFlowCount = decoder.ReadVarintU64()
	m.SumRetransFlowCount = decoder.ReadVarintU64()
	m.SumHalfOpenFlowCount = decoder.ReadVarintU64()
	m.SumPacketTx = decoder.ReadVarintU64()
	m.SumPacketRx = decoder.ReadVarintU64()
	m.SumBitTx = decoder.ReadVarintU64()
	m.SumBitRx = decoder.ReadVarintU64()
	m.SumRetransCntTx = decoder.ReadVarintU64()
	m.SumRetransCntRx = decoder.ReadVarintU64()

	m.SumRTTSyn = time.Duration(decoder.ReadVarintU64())
	m.SumRTTAvg = time.Duration(decoder.ReadVarintU64())
	m.SumARTAvg = time.Duration(decoder.ReadVarintU64())
	m.SumRTTSynFlow = decoder.ReadVarintU64()
	m.SumRTTAvgFlow = decoder.ReadVarintU64()
	m.SumARTAvgFlow = decoder.ReadVarintU64()

	m.SumZeroWndCntTx = decoder.ReadVarintU64()
	m.SumZeroWndCntRx = decoder.ReadVarintU64()
}

func (m *PerfMeterSum) concurrentMerge(other *PerfMeterSum) {
	m.SumFlowCount += other.SumFlowCount
	m.SumClosedFlowCount += other.SumClosedFlowCount
	m.SumRetransFlowCount += other.SumRetransFlowCount
	m.SumHalfOpenFlowCount += other.SumHalfOpenFlowCount
	m.SumPacketTx += other.SumPacketTx
	m.SumPacketRx += other.SumPacketRx
	m.SumBitTx += other.SumBitTx
	m.SumBitRx += other.SumBitRx
	m.SumRetransCntTx += other.SumRetransCntTx
	m.SumRetransCntRx += other.SumRetransCntRx

	m.SumRTTSyn += other.SumRTTSyn
	m.SumRTTAvg += other.SumRTTAvg
	m.SumARTAvg += other.SumARTAvg
	m.SumRTTSynFlow += other.SumRTTSynFlow
	m.SumRTTAvgFlow += other.SumRTTAvgFlow
	m.SumARTAvgFlow += other.SumARTAvgFlow

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
	m.SumBitTx += other.SumBitTx
	m.SumBitRx += other.SumBitRx
	m.SumRetransCntTx += other.SumRetransCntTx
	m.SumRetransCntRx += other.SumRetransCntRx

	m.SumRTTSyn += other.SumRTTSyn
	m.SumRTTAvg += other.SumRTTAvg
	m.SumARTAvg += other.SumARTAvg
	m.SumRTTSynFlow += other.SumRTTSynFlow
	m.SumRTTAvgFlow += other.SumRTTAvgFlow
	m.SumARTAvgFlow += other.SumARTAvgFlow

	m.SumZeroWndCntTx += other.SumZeroWndCntTx
	m.SumZeroWndCntRx += other.SumZeroWndCntRx
}

type PerfMeterMax struct {
	MaxRTTSyn time.Duration `db:"max_rtt_syn"`
	MaxRTTAvg time.Duration `db:"max_rtt_avg"`
	MaxARTAvg time.Duration `db:"max_art_avg"`
}

func (m *PerfMeterMax) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(uint64(m.MaxRTTSyn))
	encoder.WriteVarintU64(uint64(m.MaxRTTAvg))
	encoder.WriteVarintU64(uint64(m.MaxARTAvg))
}

func (m *PerfMeterMax) Decode(decoder *codec.SimpleDecoder) {
	m.MaxRTTSyn = time.Duration(decoder.ReadVarintU64())
	m.MaxRTTAvg = time.Duration(decoder.ReadVarintU64())
	m.MaxARTAvg = time.Duration(decoder.ReadVarintU64())
}

func (m *PerfMeterMax) concurrentMerge(other *PerfMeterMax) {
	m.sequentialMerge(other)
}

func (m *PerfMeterMax) sequentialMerge(other *PerfMeterMax) {
	// 注意：若有max之外的操作，需要修改concurrentMerge
	m.MaxRTTSyn = maxDuration(m.MaxRTTSyn, other.MaxRTTSyn)
	m.MaxRTTAvg = maxDuration(m.MaxRTTAvg, other.MaxRTTAvg)
	m.MaxARTAvg = maxDuration(m.MaxARTAvg, other.MaxARTAvg)
}

type PerfMeterMin struct {
	MinRTTSyn time.Duration `db:"min_rtt_syn"`
	MinRTTAvg time.Duration `db:"min_rtt_avg"`
	MinARTAvg time.Duration `db:"min_art_avg"`
}

func (m *PerfMeterMin) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(uint64(m.MinRTTSyn))
	encoder.WriteVarintU64(uint64(m.MinRTTAvg))
	encoder.WriteVarintU64(uint64(m.MinARTAvg))
}

func (m *PerfMeterMin) Decode(decoder *codec.SimpleDecoder) {
	m.MinRTTSyn = time.Duration(decoder.ReadVarintU64())
	m.MinRTTAvg = time.Duration(decoder.ReadVarintU64())
	m.MinARTAvg = time.Duration(decoder.ReadVarintU64())
}

func (m *PerfMeterMin) concurrentMerge(other *PerfMeterMin) {
	m.sequentialMerge(other)
}

func (m *PerfMeterMin) sequentialMerge(other *PerfMeterMin) {
	// 注意：若有min之外的操作，需要修改concurrentMerge
	m.MinRTTSyn = minDuration(m.MinRTTSyn, other.MinRTTSyn)
	m.MinRTTAvg = minDuration(m.MinRTTAvg, other.MinRTTAvg)
	m.MinARTAvg = minDuration(m.MinARTAvg, other.MinARTAvg)
}
