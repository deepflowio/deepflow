package zerodoc

import (
	"strconv"
	"strings"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type PlatformMeter struct {
	SumClosedFlowCount uint64 `db:"sum_closed_flow_count"`
	SumPacket          uint64 `db:"sum_packet"`
	SumBit             uint64 `db:"sum_bit"`
}

func (m *PlatformMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*PlatformMeter); ok {
		m.SumClosedFlowCount += pm.SumClosedFlowCount
		m.SumPacket += pm.SumPacket
		m.SumBit += pm.SumBit
	}
}

func (m *PlatformMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*PlatformMeter); ok {
		m.SumClosedFlowCount += pm.SumClosedFlowCount
		m.SumPacket += pm.SumPacket
		m.SumBit += pm.SumBit
	}
}

func (m *PlatformMeter) ToKVString() string {
	var buf strings.Builder
	buf.WriteString("sum_closed_flow_count=")
	buf.WriteString(strconv.FormatUint(m.SumClosedFlowCount, 10))
	buf.WriteString("i,sum_packet=")
	buf.WriteString(strconv.FormatUint(m.SumPacket, 10))
	buf.WriteString("i,sum_bit=")
	buf.WriteString(strconv.FormatUint(m.SumBit, 10))
	buf.WriteRune('i')
	return buf.String()
}
