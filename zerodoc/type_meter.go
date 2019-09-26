package zerodoc

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type TypeMeter struct {
	SumCountTClientRst       uint64 `db:"sum_count_t_c_rst"`
	SumCountTClientHalfOpen  uint64 `db:"sum_count_t_c_half_open"`
	SumCountTClientHalfClose uint64 `db:"sum_count_t_c_half_close"`
	SumCountTServerRst       uint64 `db:"sum_count_t_s_rst"`
	SumCountTServerHalfOpen  uint64 `db:"sum_count_t_s_half_open"`
	SumCountTServerHalfClose uint64 `db:"sum_count_t_s_half_close"`

	sortKey uint64
}

func (m *TypeMeter) SortKey() uint64 {
	if m.sortKey == 0 {
		m.sortKey = 1
		m.sortKey += m.SumCountTClientRst + m.SumCountTClientHalfOpen + m.SumCountTClientHalfClose
		m.sortKey += m.SumCountTServerRst + m.SumCountTServerHalfOpen + m.SumCountTServerHalfClose
	}
	return m.sortKey
}

func (m *TypeMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.SumCountTClientRst)
	encoder.WriteVarintU64(m.SumCountTClientHalfOpen)
	encoder.WriteVarintU64(m.SumCountTClientHalfClose)
	encoder.WriteVarintU64(m.SumCountTServerRst)
	encoder.WriteVarintU64(m.SumCountTServerHalfOpen)
	encoder.WriteVarintU64(m.SumCountTServerHalfClose)
}

func (m *TypeMeter) Decode(decoder *codec.SimpleDecoder) {
	m.SumCountTClientRst = decoder.ReadVarintU64()
	m.SumCountTClientHalfOpen = decoder.ReadVarintU64()
	m.SumCountTClientHalfClose = decoder.ReadVarintU64()
	m.SumCountTServerRst = decoder.ReadVarintU64()
	m.SumCountTServerHalfOpen = decoder.ReadVarintU64()
	m.SumCountTServerHalfClose = decoder.ReadVarintU64()
}

func (m *TypeMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*TypeMeter); ok {
		m.SumCountTClientRst += pm.SumCountTClientRst
		m.SumCountTClientHalfOpen += pm.SumCountTClientHalfOpen
		m.SumCountTClientHalfClose += pm.SumCountTClientHalfClose
		m.SumCountTServerRst += pm.SumCountTServerRst
		m.SumCountTServerHalfOpen += pm.SumCountTServerHalfOpen
		m.SumCountTServerHalfClose += pm.SumCountTServerHalfClose
	}
}

func (m *TypeMeter) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}

func (m *TypeMeter) ToKVString() string {
	buffer := make([]byte, app.MAX_DOC_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *TypeMeter) MarshalTo(b []byte) int {
	offset := 0

	offset += copy(b[offset:], "sum_count_t_c_rst=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountTClientRst, 10))
	offset += copy(b[offset:], "i,sum_count_t_c_half_open=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountTClientHalfOpen, 10))
	offset += copy(b[offset:], "i,sum_count_t_c_half_close=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountTClientHalfClose, 10))
	offset += copy(b[offset:], "i,sum_count_t_s_rst=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountTServerRst, 10))
	offset += copy(b[offset:], "i,sum_count_t_s_half_open=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountTServerHalfOpen, 10))
	offset += copy(b[offset:], "i,sum_count_t_s_half_close=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountTServerHalfClose, 10))
	b[offset] = 'i'
	offset++

	return offset
}

func (m *TypeMeter) Fill(IDs []uint8, values []interface{}) {
	for i, id := range IDs {
		if id <= _METER_INVALID_ || id >= _METER_MAX_ID_ || values[i] == nil {
			continue
		}
		switch id {
		case _METER_SUM_COUNT_T_C_RST:
			m.SumCountTClientRst = uint64(values[i].(int64))
		case _METER_SUM_COUNT_T_C_HALF_OPEN:
			m.SumCountTClientHalfOpen = uint64(values[i].(int64))
		case _METER_SUM_COUNT_T_C_HALF_CLOSE:
			m.SumCountTClientHalfClose = uint64(values[i].(int64))
		case _METER_SUM_COUNT_T_S_RST:
			m.SumCountTServerRst = uint64(values[i].(int64))
		case _METER_SUM_COUNT_T_S_HALF_OPEN:
			m.SumCountTServerHalfOpen = uint64(values[i].(int64))
		case _METER_SUM_COUNT_T_S_HALF_CLOSE:
			m.SumCountTServerHalfClose = uint64(values[i].(int64))
		default:
			log.Warningf("unsupport meter id=%d", id)
		}
	}
}
