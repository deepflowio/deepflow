package zerodoc

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type LogUsageMeter struct {
	SumPacketTx uint64 `db:"sum_packet_tx"`
	SumPacketRx uint64 `db:"sum_packet_rx"`
	SumBitTx    uint64 `db:"sum_bit_tx"`
	SumBitRx    uint64 `db:"sum_bit_rx"`
}

func (m *LogUsageMeter) Reverse() {
	m.SumPacketTx, m.SumPacketRx = m.SumPacketRx, m.SumPacketTx
	m.SumBitTx, m.SumBitRx = m.SumBitRx, m.SumBitTx
}

func (m *LogUsageMeter) ID() uint8 {
	return LOG_USAGE_ID
}

func (m *LogUsageMeter) Name() string {
	return MeterDFNames[LOG_USAGE_ID]
}

func (m *LogUsageMeter) VTAPName() string {
	return MeterVTAPNames[LOG_USAGE_ID]
}

func (m *LogUsageMeter) SortKey() uint64 {
	return m.SumPacketTx + m.SumPacketRx
}

func (m *LogUsageMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.SumPacketTx)
	encoder.WriteVarintU64(m.SumPacketRx)
	encoder.WriteVarintU64(m.SumBitTx)
	encoder.WriteVarintU64(m.SumBitRx)
}

func (m *LogUsageMeter) Decode(decoder *codec.SimpleDecoder) {
	m.SumPacketTx = decoder.ReadVarintU64()
	m.SumPacketRx = decoder.ReadVarintU64()
	m.SumBitTx = decoder.ReadVarintU64()
	m.SumBitRx = decoder.ReadVarintU64()
}

func (m *LogUsageMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*LogUsageMeter); ok {
		m.SumPacketTx += pm.SumPacketTx
		m.SumPacketRx += pm.SumPacketRx
		m.SumBitTx += pm.SumBitTx
		m.SumBitRx += pm.SumBitRx
	}
}

func (m *LogUsageMeter) SequentialMerge(other app.Meter) { // other为后一个时间的统计量
	if pm, ok := other.(*LogUsageMeter); ok {
		m.SumPacketTx += pm.SumPacketTx
		m.SumPacketRx += pm.SumPacketRx
		m.SumBitTx += pm.SumBitTx
		m.SumBitRx += pm.SumBitRx
	}
}

func (m *LogUsageMeter) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *LogUsageMeter) MarshalTo(b []byte) int {
	offset := 0

	offset += copy(b[offset:], "sum_packet_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumPacketTx, 10))
	offset += copy(b[offset:], "i,sum_packet_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumPacketRx, 10))
	offset += copy(b[offset:], "i,sum_bit_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumBitTx, 10))
	offset += copy(b[offset:], "i,sum_bit_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumBitRx, 10))
	b[offset] = 'i'
	offset++

	return offset
}

func (m *LogUsageMeter) Fill(ids []uint8, values []interface{}) {
	for i, id := range ids {
		if id <= _METER_INVALID_ || id >= _METER_MAX_ID_ || values[i] == nil {
			continue
		}
		switch id {
		case _METER_SUM_PACKET_TX:
			m.SumPacketTx = uint64(values[i].(int64))
		case _METER_SUM_PACKET_RX:
			m.SumPacketRx = uint64(values[i].(int64))
		case _METER_SUM_BIT_TX:
			m.SumBitTx = uint64(values[i].(int64))
		case _METER_SUM_BIT_RX:
			m.SumBitRx = uint64(values[i].(int64))
		default:
			log.Warningf("unsupport meter id=%d", id)
		}
	}
}
