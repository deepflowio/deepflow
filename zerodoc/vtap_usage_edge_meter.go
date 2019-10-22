package zerodoc

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type VTAPUsageEdgeMeter Metrics

func (m *VTAPUsageEdgeMeter) Encode(encoder *codec.SimpleEncoder) {
	(*Metrics)(m).Encode(encoder)
}

func (m *VTAPUsageEdgeMeter) Decode(decoder *codec.SimpleDecoder) {
	(*Metrics)(m).Decode(decoder)
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
		(*Metrics)(m).Merge((*Metrics)(other))
	}
}

func (m *VTAPUsageEdgeMeter) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}
