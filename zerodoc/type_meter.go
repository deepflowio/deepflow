package zerodoc

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type TypeMeter struct {
	SumCountL0S1S  uint64 `db:"sum_count_l_0s1s"`
	SumCountL1S5S  uint64 `db:"sum_count_l_1s5s"`
	SumCountL5S10S uint64 `db:"sum_count_l_5s10s"`
	SumCountL10S1M uint64 `db:"sum_count_l_10s1m"`
	SumCountL1M1H  uint64 `db:"sum_count_l_1m1h"`
	SumCountL1H    uint64 `db:"sum_count_l_1h"`

	SumCountE0K10K   uint64 `db:"sum_count_e_0k10k"`
	SumCountE10K100K uint64 `db:"sum_count_e_10k100k"`
	SumCountE100K1M  uint64 `db:"sum_count_e_100k1m"`
	SumCountE1M100M  uint64 `db:"sum_count_e_1m100m"`
	SumCountE100M1G  uint64 `db:"sum_count_e_100m1g"`
	SumCountE1G      uint64 `db:"sum_count_e_1g"`

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
	encoder.WriteU64(m.SumCountL0S1S)
	encoder.WriteU64(m.SumCountL1S5S)
	encoder.WriteU64(m.SumCountL5S10S)
	encoder.WriteU64(m.SumCountL10S1M)
	encoder.WriteU64(m.SumCountL1M1H)
	encoder.WriteU64(m.SumCountL1H)

	encoder.WriteU64(m.SumCountE0K10K)
	encoder.WriteU64(m.SumCountE10K100K)
	encoder.WriteU64(m.SumCountE100K1M)
	encoder.WriteU64(m.SumCountE1M100M)
	encoder.WriteU64(m.SumCountE100M1G)
	encoder.WriteU64(m.SumCountE1G)

	encoder.WriteU64(m.SumCountTClientRst)
	encoder.WriteU64(m.SumCountTClientHalfOpen)
	encoder.WriteU64(m.SumCountTClientHalfClose)
	encoder.WriteU64(m.SumCountTServerRst)
	encoder.WriteU64(m.SumCountTServerHalfOpen)
	encoder.WriteU64(m.SumCountTServerHalfClose)
}

func (m *TypeMeter) Decode(decoder *codec.SimpleDecoder) {
	m.SumCountL0S1S = decoder.ReadU64()
	m.SumCountL1S5S = decoder.ReadU64()
	m.SumCountL5S10S = decoder.ReadU64()
	m.SumCountL10S1M = decoder.ReadU64()
	m.SumCountL1M1H = decoder.ReadU64()
	m.SumCountL1H = decoder.ReadU64()

	m.SumCountE0K10K = decoder.ReadU64()
	m.SumCountE10K100K = decoder.ReadU64()
	m.SumCountE100K1M = decoder.ReadU64()
	m.SumCountE1M100M = decoder.ReadU64()
	m.SumCountE100M1G = decoder.ReadU64()
	m.SumCountE1G = decoder.ReadU64()

	m.SumCountTClientRst = decoder.ReadU64()
	m.SumCountTClientHalfOpen = decoder.ReadU64()
	m.SumCountTClientHalfClose = decoder.ReadU64()
	m.SumCountTServerRst = decoder.ReadU64()
	m.SumCountTServerHalfOpen = decoder.ReadU64()
	m.SumCountTServerHalfClose = decoder.ReadU64()
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
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *TypeMeter) MarshalTo(b []byte) int {
	offset := 0

	offset += copy(b[offset:], "sum_count_l_0s1s=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountL0S1S, 10))
	offset += copy(b[offset:], "i,sum_count_l_1s5s=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountL1S5S, 10))
	offset += copy(b[offset:], "i,sum_count_l_5s10s=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountL5S10S, 10))
	offset += copy(b[offset:], "i,sum_count_l_10s1m=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountL10S1M, 10))
	offset += copy(b[offset:], "i,sum_count_l_1m1h=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountL1M1H, 10))
	offset += copy(b[offset:], "i,sum_count_l_1h=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountL1H, 10))

	offset += copy(b[offset:], "i,sum_count_e_0k10k=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountE0K10K, 10))
	offset += copy(b[offset:], "i,sum_count_e_10k100k=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountE10K100K, 10))
	offset += copy(b[offset:], "i,sum_count_e_100k1m=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountE100K1M, 10))
	offset += copy(b[offset:], "i,sum_count_e_1m100m=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountE1M100M, 10))
	offset += copy(b[offset:], "i,sum_count_e_100m1g=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountE100M1G, 10))
	offset += copy(b[offset:], "i,sum_count_e_1g=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumCountE1G, 10))

	offset += copy(b[offset:], "i,sum_count_t_c_rst=")
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
