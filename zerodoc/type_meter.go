package zerodoc

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type TypeMeter struct {
	SumCountL0S1S  uint64 `db:"sum_count_l_0s1s"`  // 废弃
	SumCountL1S5S  uint64 `db:"sum_count_l_1s5s"`  // 废弃
	SumCountL5S10S uint64 `db:"sum_count_l_5s10s"` // 废弃
	SumCountL10S1M uint64 `db:"sum_count_l_10s1m"` // 废弃
	SumCountL1M1H  uint64 `db:"sum_count_l_1m1h"`  // 废弃
	SumCountL1H    uint64 `db:"sum_count_l_1h"`    // 废弃

	SumCountE0K10K   uint64 `db:"sum_count_e_0k10k"`   // 废弃
	SumCountE10K100K uint64 `db:"sum_count_e_10k100k"` // 废弃
	SumCountE100K1M  uint64 `db:"sum_count_e_100k1m"`  // 废弃
	SumCountE1M100M  uint64 `db:"sum_count_e_1m100m"`  // 废弃
	SumCountE100M1G  uint64 `db:"sum_count_e_100m1g"`  // 废弃
	SumCountE1G      uint64 `db:"sum_count_e_1g"`      // 废弃

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
		m.sortKey = m.SumCountL0S1S + m.SumCountL1S5S + m.SumCountL5S10S + m.SumCountL10S1M + m.SumCountL1M1H + m.SumCountL1H + 1
	}
	return m.sortKey
}

func (m *TypeMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.SumCountL0S1S)
	encoder.WriteVarintU64(m.SumCountL1S5S)
	encoder.WriteVarintU64(m.SumCountL5S10S)
	encoder.WriteVarintU64(m.SumCountL10S1M)
	encoder.WriteVarintU64(m.SumCountL1M1H)
	encoder.WriteVarintU64(m.SumCountL1H)

	encoder.WriteVarintU64(m.SumCountE0K10K)
	encoder.WriteVarintU64(m.SumCountE10K100K)
	encoder.WriteVarintU64(m.SumCountE100K1M)
	encoder.WriteVarintU64(m.SumCountE1M100M)
	encoder.WriteVarintU64(m.SumCountE100M1G)
	encoder.WriteVarintU64(m.SumCountE1G)

	encoder.WriteVarintU64(m.SumCountTClientRst)
	encoder.WriteVarintU64(m.SumCountTClientHalfOpen)
	encoder.WriteVarintU64(m.SumCountTClientHalfClose)
	encoder.WriteVarintU64(m.SumCountTServerRst)
	encoder.WriteVarintU64(m.SumCountTServerHalfOpen)
	encoder.WriteVarintU64(m.SumCountTServerHalfClose)
}

func (m *TypeMeter) Decode(decoder *codec.SimpleDecoder) {
	m.SumCountL0S1S = decoder.ReadVarintU64()
	m.SumCountL1S5S = decoder.ReadVarintU64()
	m.SumCountL5S10S = decoder.ReadVarintU64()
	m.SumCountL10S1M = decoder.ReadVarintU64()
	m.SumCountL1M1H = decoder.ReadVarintU64()
	m.SumCountL1H = decoder.ReadVarintU64()

	m.SumCountE0K10K = decoder.ReadVarintU64()
	m.SumCountE10K100K = decoder.ReadVarintU64()
	m.SumCountE100K1M = decoder.ReadVarintU64()
	m.SumCountE1M100M = decoder.ReadVarintU64()
	m.SumCountE100M1G = decoder.ReadVarintU64()
	m.SumCountE1G = decoder.ReadVarintU64()

	m.SumCountTClientRst = decoder.ReadVarintU64()
	m.SumCountTClientHalfOpen = decoder.ReadVarintU64()
	m.SumCountTClientHalfClose = decoder.ReadVarintU64()
	m.SumCountTServerRst = decoder.ReadVarintU64()
	m.SumCountTServerHalfOpen = decoder.ReadVarintU64()
	m.SumCountTServerHalfClose = decoder.ReadVarintU64()
}

func (m *TypeMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*TypeMeter); ok {
		m.SumCountL0S1S += pm.SumCountL0S1S
		m.SumCountL1S5S += pm.SumCountL1S5S
		m.SumCountL5S10S += pm.SumCountL5S10S
		m.SumCountL10S1M += pm.SumCountL10S1M
		m.SumCountL1M1H += pm.SumCountL1M1H
		m.SumCountL1H += pm.SumCountL1H

		m.SumCountE0K10K += pm.SumCountE0K10K
		m.SumCountE10K100K += pm.SumCountE10K100K
		m.SumCountE100K1M += pm.SumCountE100K1M
		m.SumCountE1M100M += pm.SumCountE1M100M
		m.SumCountE100M1G += pm.SumCountE100M1G
		m.SumCountE1G += pm.SumCountE1G

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

func (m *TypeMeter) Fill(isTag []bool, names []string, values []interface{}) {
	for i, name := range names {
		if isTag[i] || values[i] == nil {
			continue
		}
		switch name {
		case "sum_count_t_c_rst":
			m.SumCountTClientRst = uint64(values[i].(int64))
		case "sum_count_t_c_half_open":
			m.SumCountTClientHalfOpen = uint64(values[i].(int64))
		case "sum_count_t_c_half_close":
			m.SumCountTClientHalfClose = uint64(values[i].(int64))
		case "sum_count_t_s_rst":
			m.SumCountTServerRst = uint64(values[i].(int64))
		case "sum_count_t_s_half_open":
			m.SumCountTServerHalfOpen = uint64(values[i].(int64))
		case "sum_count_t_s_half_close":
			m.SumCountTServerHalfClose = uint64(values[i].(int64))
		}
	}
}
