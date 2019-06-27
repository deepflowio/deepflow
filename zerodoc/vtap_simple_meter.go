package zerodoc

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

// 该meter接收从influxdb streaming返回的vtap_usage数据
// influxdb每返回-行数据，打一个VTAPSimpleMeter 的doc
// 由于用VTAPUsageMeter的结构返回数据太冗余了,故用这个结构即可
type VTAPSimpleMeter struct {
	Metrics
}

func (m *VTAPSimpleMeter) Encode(encoder *codec.SimpleEncoder) {
	m.Metrics.Encode(encoder)
}

func (m *VTAPSimpleMeter) Decode(decoder *codec.SimpleDecoder) {
	m.Metrics.Decode(decoder)
}

func (m *VTAPSimpleMeter) SortKey() uint64 {
	panic("not supported!")
}

func (m *VTAPSimpleMeter) ToKVString() string {
	panic("not supported!")
}

func (m *VTAPSimpleMeter) MarshalTo(b []byte) int {
	panic("not supported!")
}

func (m *VTAPSimpleMeter) Fill(isTag []bool, names []string, values []interface{}) {
	for i, name := range names {
		if isTag[i] || values[i] == nil {
			continue
		}
		switch name {
		case "tx_bytes":
			m.TxBytes = uint32(values[i].(int64))
		case "rx_bytes":
			m.RxBytes = uint32(values[i].(int64))
		case "tx_packets":
			m.TxPackets = uint32(values[i].(int64))
		case "rx_packets":
			m.RxPackets = uint32(values[i].(int64))
		}
	}
}

func (m *VTAPSimpleMeter) ConcurrentMerge(other app.Meter) {
	if other, ok := other.(*VTAPSimpleMeter); ok {
		m.Merge(&other.Metrics)
	}
}

func (m *VTAPSimpleMeter) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}
