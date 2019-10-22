package zerodoc

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type Metrics struct {
	TxBytes   uint64
	RxBytes   uint64
	TxPackets uint64
	RxPackets uint64
}

type VTAPUsageMeter Metrics

func (m *Metrics) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.TxBytes)
	encoder.WriteVarintU64(m.RxBytes)
	encoder.WriteVarintU64(m.TxPackets)
	encoder.WriteVarintU64(m.RxPackets)
}

func (m *Metrics) Decode(decoder *codec.SimpleDecoder) {
	m.TxBytes = decoder.ReadVarintU64()
	m.RxBytes = decoder.ReadVarintU64()
	m.TxPackets = decoder.ReadVarintU64()
	m.RxPackets = decoder.ReadVarintU64()
}

func (m *Metrics) SortKey() uint64 {
	return uint64(m.TxBytes) + uint64(m.RxBytes)
}

func (m *Metrics) ToKVString() string {
	panic("not supported!")
}

func (m *Metrics) MarshalTo(b []byte) int {
	panic("not supported!")
}

func (m *Metrics) Clone() app.Meter {
	panic("not supported!")
}

func (m *Metrics) Release() {
	panic("not supported!")
}

func (m *Metrics) Merge(other *Metrics) {
	m.TxBytes += other.TxBytes
	m.RxBytes += other.RxBytes
	m.TxPackets += other.TxPackets
	m.RxPackets += other.RxPackets
}

func (m *Metrics) ConcurrentMerge(other app.Meter) {
	if other, ok := other.(*Metrics); ok {
		m.Merge(other)
	}
}

func (m *Metrics) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}

func (m *VTAPUsageMeter) Encode(encoder *codec.SimpleEncoder) {
	(*Metrics)(m).Encode(encoder)
}

func (m *VTAPUsageMeter) Decode(decoder *codec.SimpleDecoder) {
	(*Metrics)(m).Decode(decoder)
}

func (m *VTAPUsageMeter) SortKey() uint64 {
	panic("not supported!")
}

func (m *VTAPUsageMeter) ToKVString() string {
	panic("not supported!")
}

func (m *VTAPUsageMeter) MarshalTo(b []byte) int {
	panic("not supported!")
}

func (m *VTAPUsageMeter) ConcurrentMerge(other app.Meter) {
	if other, ok := other.(*VTAPUsageMeter); ok {
		(*Metrics)(m).Merge((*Metrics)(other))
	}
}

func (m *VTAPUsageMeter) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}
