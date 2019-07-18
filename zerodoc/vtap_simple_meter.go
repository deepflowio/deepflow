package zerodoc

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

// 该meter接收从influxdb streaming返回的vtap_usage数据
// influxdb每返回-行数据，打一个VTAPSimpleMeter 的doc
// 由于用VTAPUsageMeter的结构返回数据太冗余了,故用这个结构即可
type VTAPSimpleMeter struct {
	TxBytes   uint64 `db:"tx_bytes"`
	RxBytes   uint64 `db:"rx_bytes"`
	Bytes     uint64 `db:"bytes"`
	TxPackets uint64 `db:"tx_packets"`
	RxPackets uint64 `db:"rx_packets"`
	Packets   uint64 `db:"packets"`
}

func (m *VTAPSimpleMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU64(m.TxBytes)
	encoder.WriteU64(m.RxBytes)
	encoder.WriteU64(m.Bytes)
	encoder.WriteU64(m.TxPackets)
	encoder.WriteU64(m.RxPackets)
	encoder.WriteU64(m.Packets)
}

func (m *VTAPSimpleMeter) Decode(decoder *codec.SimpleDecoder) {
	m.TxBytes = decoder.ReadU64()
	m.RxBytes = decoder.ReadU64()
	m.Bytes = decoder.ReadU64()
	m.TxPackets = decoder.ReadU64()
	m.RxPackets = decoder.ReadU64()
	m.Packets = decoder.ReadU64()
}

func (m *VTAPSimpleMeter) Merge(other *VTAPSimpleMeter) {
	m.TxBytes += other.TxBytes
	m.RxBytes += other.RxBytes
	m.Bytes += other.Bytes
	m.TxPackets += other.TxPackets
	m.RxPackets += other.RxPackets
	m.Packets += other.Packets
}

func (m *VTAPSimpleMeter) SortKey() uint64 {
	panic("not supported!")
}

func (m *VTAPSimpleMeter) ToKVString() string {
	buffer := make([]byte, app.MAX_DOC_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *VTAPSimpleMeter) MarshalTo(b []byte) int {
	offset := 0
	offset += copy(b[offset:], "tx_bytes=")
	offset += copy(b[offset:], strconv.FormatUint(m.TxBytes, 10))
	offset += copy(b[offset:], "i,rx_bytes=")
	offset += copy(b[offset:], strconv.FormatUint(m.RxBytes, 10))
	offset += copy(b[offset:], "i,bytes=")
	offset += copy(b[offset:], strconv.FormatUint(m.Bytes, 10))
	offset += copy(b[offset:], "i,tx_packets=")
	offset += copy(b[offset:], strconv.FormatUint(m.TxPackets, 10))
	offset += copy(b[offset:], "i,rx_packets=")
	offset += copy(b[offset:], strconv.FormatUint(m.RxPackets, 10))
	offset += copy(b[offset:], "i,packets=")
	offset += copy(b[offset:], strconv.FormatUint(m.Packets, 10))
	b[offset] = 'i'
	offset++

	return offset
}

func (m *VTAPSimpleMeter) SetValue(s *Metrics) {
	m.TxBytes = s.TxBytes
	m.RxBytes = s.RxBytes
	m.Bytes = s.TxBytes + s.RxBytes
	m.TxPackets = s.TxPackets
	m.RxPackets = s.RxPackets
	m.Packets = s.TxPackets + s.RxPackets
}

func (m *VTAPSimpleMeter) Fill(isTag []bool, names []string, values []interface{}) {
	for i, name := range names {
		if isTag[i] || values[i] == nil {
			continue
		}
		switch name {
		case "tx_bytes":
			m.TxBytes = uint64(values[i].(int64))
		case "rx_bytes":
			m.RxBytes = uint64(values[i].(int64))
		case "bytes":
			m.Bytes = uint64(values[i].(int64))
		case "tx_packets":
			m.TxPackets = uint64(values[i].(int64))
		case "rx_packets":
			m.RxPackets = uint64(values[i].(int64))
		case "packets":
			m.Packets = uint64(values[i].(int64))
		}
	}
}

func (m *VTAPSimpleMeter) ConcurrentMerge(other app.Meter) {
	if other, ok := other.(*VTAPSimpleMeter); ok {
		m.Merge(other)
	}
}

func (m *VTAPSimpleMeter) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}
