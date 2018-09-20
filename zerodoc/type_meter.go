package zerodoc

import (
	"strconv"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type TypeMeter struct {
	SumCountL0S1S  uint64
	SumCountL1S5S  uint64
	SumCountL5S10S uint64
	SumCountL10S1M uint64
	SumCountL1M1H  uint64
	SumCountL1H    uint64

	SumCountE0K10K   uint64
	SumCountE10K100K uint64
	SumCountE100K1M  uint64
	SumCountE1M100M  uint64
	SumCountE100M1G  uint64
	SumCountE1G      uint64

	SumCountTClientRst       uint64
	SumCountTClientHalfOpen  uint64
	SumCountTClientHalfClose uint64
	SumCountTServerRst       uint64
	SumCountTServerHalfOpen  uint64
	SumCountTServerHalfClose uint64
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
	var buf strings.Builder
	// TODO: 预计算string长度

	buf.WriteString("i,sum_count_l_0s1s=")
	buf.WriteString(strconv.FormatUint(m.SumCountL0S1S, 10))
	buf.WriteString("i,sum_count_l_1s5s=")
	buf.WriteString(strconv.FormatUint(m.SumCountL1S5S, 10))
	buf.WriteString("i,sum_count_l_5s10s=")
	buf.WriteString(strconv.FormatUint(m.SumCountL5S10S, 10))
	buf.WriteString("i,sum_count_l_10s1m=")
	buf.WriteString(strconv.FormatUint(m.SumCountL10S1M, 10))
	buf.WriteString("i,sum_count_l_1m1h=")
	buf.WriteString(strconv.FormatUint(m.SumCountL1M1H, 10))
	buf.WriteString("i,sum_count_l_1h=")
	buf.WriteString(strconv.FormatUint(m.SumCountL1H, 10))

	buf.WriteString("i,sum_count_e_0k10k=")
	buf.WriteString(strconv.FormatUint(m.SumCountE0K10K, 10))
	buf.WriteString("i,sum_count_e_10k100k=")
	buf.WriteString(strconv.FormatUint(m.SumCountE10K100K, 10))
	buf.WriteString("i,sum_count_e_100k1m=")
	buf.WriteString(strconv.FormatUint(m.SumCountE100K1M, 10))
	buf.WriteString("i,sum_count_e_1m100m=")
	buf.WriteString(strconv.FormatUint(m.SumCountE1M100M, 10))
	buf.WriteString("i,sum_count_e_100m1g=")
	buf.WriteString(strconv.FormatUint(m.SumCountE100M1G, 10))
	buf.WriteString("i,sum_count_e_1g=")
	buf.WriteString(strconv.FormatUint(m.SumCountE1G, 10))

	buf.WriteString("i,sum_count_t_c_rst=")
	buf.WriteString(strconv.FormatUint(m.SumCountTClientRst, 10))
	buf.WriteString("i,sum_count_t_c_half_open=")
	buf.WriteString(strconv.FormatUint(m.SumCountTClientHalfOpen, 10))
	buf.WriteString("i,sum_count_t_c_half_close=")
	buf.WriteString(strconv.FormatUint(m.SumCountTClientHalfClose, 10))
	buf.WriteString("i,sum_count_t_s_rst=")
	buf.WriteString(strconv.FormatUint(m.SumCountTServerRst, 10))
	buf.WriteString("i,sum_count_t_s_half_open=")
	buf.WriteString(strconv.FormatUint(m.SumCountTServerHalfOpen, 10))
	buf.WriteString("i,sum_count_t_s_half_close=")
	buf.WriteString(strconv.FormatUint(m.SumCountTServerHalfClose, 10))
	buf.WriteRune('i')

	return buf.String()
}
