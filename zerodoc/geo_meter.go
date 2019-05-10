package zerodoc

import (
	"strconv"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type GeoMeter struct {
	SumClosedFlowCount    uint64        `db:"sum_closed_flow_count"`
	SumAbnormalFlowCount  uint64        `db:"sum_abnormal_flow_count"`
	SumClosedFlowDuration uint64        `db:"sum_closed_flow_duration"` // ms
	SumPacketTx           uint64        `db:"sum_packet_tx"`
	SumPacketRx           uint64        `db:"sum_packet_rx"`
	SumBitTx              uint64        `db:"sum_bit_tx"`
	SumBitRx              uint64        `db:"sum_bit_rx"`
	SumRTTSynClient       time.Duration `db:"sum_rtt_syn_client"`
	SumRTTSynClientFlow   uint64        `db:"sum_rtt_syn_client_flow"`
}

func (m *GeoMeter) SortKey() uint64 {
	return m.SumPacketTx + m.SumPacketRx
}

func (m *GeoMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.SumClosedFlowCount)
	encoder.WriteVarintU64(m.SumAbnormalFlowCount)
	encoder.WriteVarintU64(m.SumClosedFlowDuration)
	encoder.WriteVarintU64(m.SumPacketTx)
	encoder.WriteVarintU64(m.SumPacketRx)
	encoder.WriteVarintU64(m.SumBitTx)
	encoder.WriteVarintU64(m.SumBitRx)
	encoder.WriteVarintU64(uint64(m.SumRTTSynClient))
	encoder.WriteVarintU64(m.SumRTTSynClientFlow)
}

func (m *GeoMeter) Decode(decoder *codec.SimpleDecoder) {
	m.SumClosedFlowCount = decoder.ReadVarintU64()
	m.SumAbnormalFlowCount = decoder.ReadVarintU64()
	m.SumClosedFlowDuration = decoder.ReadVarintU64()
	m.SumPacketTx = decoder.ReadVarintU64()
	m.SumPacketRx = decoder.ReadVarintU64()
	m.SumBitTx = decoder.ReadVarintU64()
	m.SumBitRx = decoder.ReadVarintU64()
	m.SumRTTSynClient = time.Duration(decoder.ReadVarintU64())
	m.SumRTTSynClientFlow = decoder.ReadVarintU64()
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
		m.SumRTTSynClient += pgm.SumRTTSynClient
		m.SumRTTSynClientFlow += pgm.SumRTTSynClientFlow
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
		m.SumRTTSynClient += pgm.SumRTTSynClient
		m.SumRTTSynClientFlow += pgm.SumRTTSynClientFlow
	}
}

func (m *GeoMeter) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *GeoMeter) MarshalTo(b []byte) int {
	offset := 0

	offset += copy(b[offset:], "sum_closed_flow_count=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumClosedFlowCount, 10))
	offset += copy(b[offset:], "i,sum_abnormal_flow_count=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumAbnormalFlowCount, 10))
	offset += copy(b[offset:], "i,sum_closed_flow_duration=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumClosedFlowDuration*1000, 10)) // us
	offset += copy(b[offset:], "i,sum_packet_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumPacketTx, 10))
	offset += copy(b[offset:], "i,sum_packet_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumPacketRx, 10))
	offset += copy(b[offset:], "i,sum_bit_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumBitTx, 10))
	offset += copy(b[offset:], "i,sum_bit_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumBitRx, 10))
	offset += copy(b[offset:], "i,sum_rtt_syn_client=")
	offset += copy(b[offset:], strconv.FormatInt(int64(m.SumRTTSynClient/time.Microsecond), 10))
	offset += copy(b[offset:], "i,sum_rtt_syn_client_flow=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumRTTSynClientFlow, 10))
	b[offset] = 'i'
	offset++

	return offset
}
