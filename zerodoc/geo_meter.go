package zerodoc

import (
	"strconv"
	"strings"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type GeoMeter struct {
	SumClosedFlowCount    uint64        `db:"sum_closed_flow_count"`
	SumAbnormalFlowCount  uint64        `db:"sum_abnormal_flow_count"`
	SumClosedFlowDuration time.Duration `db:"sum_closed_flow_duration"`
	SumPacketTx           uint64        `db:"sum_packet_tx"`
	SumPacketRx           uint64        `db:"sum_packet_rx"`
	SumBitTx              uint64        `db:"sum_bit_tx"`
	SumBitRx              uint64        `db:"sum_bit_rx"`
	SumRTTSyn             time.Duration `db:"sum_rtt_syn"`
	SumRTTSynFlow         uint64        `db:"sum_rtt_syn_flow"`
}

func (m *GeoMeter) SortKey() uint64 {
	return m.SumPacketTx + m.SumPacketRx
}

func (m *GeoMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU64(m.SumClosedFlowCount)
	encoder.WriteU64(m.SumAbnormalFlowCount)
	encoder.WriteU64(uint64(m.SumClosedFlowDuration))
	encoder.WriteU64(m.SumPacketTx)
	encoder.WriteU64(m.SumPacketRx)
	encoder.WriteU64(m.SumBitTx)
	encoder.WriteU64(m.SumBitRx)
	encoder.WriteU64(uint64(m.SumRTTSyn))
	encoder.WriteU64(m.SumRTTSynFlow)
}

func (m *GeoMeter) Decode(decoder *codec.SimpleDecoder) {
	m.SumClosedFlowCount = decoder.ReadU64()
	m.SumAbnormalFlowCount = decoder.ReadU64()
	m.SumClosedFlowDuration = time.Duration(decoder.ReadU64())
	m.SumPacketTx = decoder.ReadU64()
	m.SumPacketRx = decoder.ReadU64()
	m.SumBitTx = decoder.ReadU64()
	m.SumBitRx = decoder.ReadU64()
	m.SumRTTSyn = time.Duration(decoder.ReadU64())
	m.SumRTTSynFlow = decoder.ReadU64()
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
