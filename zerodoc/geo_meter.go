package zerodoc

import (
	"strconv"
	"strings"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type GeoMeter struct {
	SumClosedFlowCount    uint64
	SumAbnormalFlowCount  uint64
	SumClosedFlowDuration time.Duration
	SumPacketTx           uint64
	SumPacketRx           uint64
	SumBitTx              uint64
	SumBitRx              uint64
	SumRTTSyn             time.Duration
	SumRTTSynFlow         uint64
}

func (m *GeoMeter) ConcurrentMerge(other app.Meter) {
	if pgm, ok := other.(*GeoMeter); ok {
		m.SumClosedFlowCount += pgm.SumClosedFlowCount
		m.SumAbnormalFlowCount += pgm.SumAbnormalFlowCount
		m.SumClosedFlowDuration += pgm.SumClosedFlowDuration
		m.SumPacketTx += pgm.SumPacketTx
		m.SumPacketRx += pgm.SumPacketRx
		m.SumBitTx += pgm.SumBitTx
		m.SumBitRx += pgm.SumBitRx
		m.SumRTTSyn += pgm.SumRTTSyn
		m.SumRTTSynFlow += pgm.SumRTTSynFlow
	}
}

func (m *GeoMeter) SequentialMerge(other app.Meter) {
	if pgm, ok := other.(*GeoMeter); ok {
		m.SumClosedFlowCount += pgm.SumClosedFlowCount
		m.SumAbnormalFlowCount += pgm.SumAbnormalFlowCount
		m.SumClosedFlowDuration += pgm.SumClosedFlowDuration
		m.SumPacketTx += pgm.SumPacketTx
		m.SumPacketRx += pgm.SumPacketRx
		m.SumBitTx += pgm.SumBitTx
		m.SumBitRx += pgm.SumBitRx
		m.SumRTTSyn += pgm.SumRTTSyn
		m.SumRTTSynFlow += pgm.SumRTTSynFlow
	}
}

func (m *GeoMeter) ToKVString() string {
	var buf strings.Builder

	buf.WriteString("sum_closed_flow_count=")
	buf.WriteString(strconv.FormatUint(m.SumClosedFlowCount, 10))
	buf.WriteString("i,sum_abnormal_flow_count=")
	buf.WriteString(strconv.FormatUint(m.SumAbnormalFlowCount, 10))
	buf.WriteString("i,sum_closed_flow_duration=")
	buf.WriteString(strconv.FormatInt(int64(m.SumClosedFlowDuration/time.Microsecond), 10))
	buf.WriteString("i,sum_packet_tx=")
	buf.WriteString(strconv.FormatUint(m.SumPacketTx, 10))
	buf.WriteString("i,sum_packet_rx=")
	buf.WriteString(strconv.FormatUint(m.SumPacketRx, 10))
	buf.WriteString("i,sum_bit_tx=")
	buf.WriteString(strconv.FormatUint(m.SumBitTx, 10))
	buf.WriteString("i,sum_bit_rx=")
	buf.WriteString(strconv.FormatUint(m.SumBitRx, 10))
	buf.WriteString("i,sum_rtt_syn=")
	buf.WriteString(strconv.FormatInt(int64(m.SumRTTSyn/time.Microsecond), 10))
	buf.WriteString("i,sum_rtt_syn_flow=")
	buf.WriteString(strconv.FormatUint(m.SumRTTSynFlow, 10))
	buf.WriteRune('i')

	return buf.String()
}

func (m *GeoMeter) Duplicate() app.Meter {
	dup := *m
	return &dup
}
