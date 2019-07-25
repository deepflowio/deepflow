package zerodoc

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type VTAPUsageEdgeMeter struct {
	Fields MetricsField

	TCP    Metrics
	UDP    Metrics
	Others Metrics
}

func (m *VTAPUsageEdgeMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU32(uint32(m.Fields))

	if m.Fields&METRICS_TCP != 0 {
		m.TCP.Encode(encoder)
	}
	if m.Fields&METRICS_UDP != 0 {
		m.UDP.Encode(encoder)
	}
	if m.Fields&METRICS_OTHERS != 0 {
		m.Others.Encode(encoder)
	}
}

func (m *VTAPUsageEdgeMeter) Decode(decoder *codec.SimpleDecoder) {
	m.Fields = MetricsField(decoder.ReadU32())

	if m.Fields&METRICS_TCP != 0 {
		m.TCP.Decode(decoder)
	}
	if m.Fields&METRICS_UDP != 0 {
		m.UDP.Decode(decoder)
	}
	if m.Fields&METRICS_OTHERS != 0 {
		m.Others.Decode(decoder)
	}
}

func (m *VTAPUsageEdgeMeter) SortKey() uint64 {
	panic("not supported!")
}

func (m *VTAPUsageEdgeMeter) ToKVString() string {
	panic("not supported!")
}

func (m *VTAPUsageEdgeMeter) MarshalTo(b []byte) int {
	panic("not supported!")
}

func (m *VTAPUsageEdgeMeter) ConcurrentMerge(other app.Meter) {
	if other, ok := other.(*VTAPUsageEdgeMeter); ok {
		m.Fields |= other.Fields

		if m.Fields&METRICS_TCP != 0 {
			m.TCP.Merge(&other.TCP)
		}
		if m.Fields&METRICS_UDP != 0 {
			m.UDP.Merge(&other.UDP)
		}
		if m.Fields&METRICS_OTHERS != 0 {
			m.Others.Merge(&other.Others)
		}
	}
}

func (m *VTAPUsageEdgeMeter) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}
