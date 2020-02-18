package zerodoc

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type VTAPUsageMeter struct {
	TxBytes   uint64 `db:"tx_bytes"`
	RxBytes   uint64 `db:"rx_bytes"`
	TxPackets uint64 `db:"tx_packets"`
	RxPackets uint64 `db:"rx_packets"`
}

func (m *VTAPUsageMeter) Reverse() {
	m.TxBytes, m.RxBytes = m.RxBytes, m.TxBytes
	m.TxPackets, m.RxPackets = m.RxPackets, m.TxPackets
}

func (m *VTAPUsageMeter) ID() uint8 {
	return VTAP_USAGE_ID
}

func (m *VTAPUsageMeter) Name() string {
	return MeterDFNames[VTAP_USAGE_ID]
}

func (m *VTAPUsageMeter) VTAPName() string {
	return MeterVTAPNames[VTAP_USAGE_ID]
}

func (m *VTAPUsageMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.TxBytes)
	encoder.WriteVarintU64(m.RxBytes)
	encoder.WriteVarintU64(m.TxPackets)
	encoder.WriteVarintU64(m.RxPackets)
}

func (m *VTAPUsageMeter) Decode(decoder *codec.SimpleDecoder) {
	m.TxBytes = decoder.ReadVarintU64()
	m.RxBytes = decoder.ReadVarintU64()
	m.TxPackets = decoder.ReadVarintU64()
	m.RxPackets = decoder.ReadVarintU64()
}

func (m *VTAPUsageMeter) SortKey() uint64 {
	return uint64(m.TxBytes) + uint64(m.RxBytes)
}

func (m *VTAPUsageMeter) ToKVString() string {
	buffer := make([]byte, app.MAX_DOC_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *VTAPUsageMeter) MarshalTo(b []byte) int {
	offset := 0
	offset += copy(b[offset:], "tx_bytes=")
	offset += copy(b[offset:], strconv.FormatUint(m.TxBytes, 10))
	offset += copy(b[offset:], "i,rx_bytes=")
	offset += copy(b[offset:], strconv.FormatUint(m.RxBytes, 10))
	offset += copy(b[offset:], "i,bytes=")
	offset += copy(b[offset:], strconv.FormatUint(m.TxBytes+m.RxBytes, 10))
	offset += copy(b[offset:], "i,tx_packets=")
	offset += copy(b[offset:], strconv.FormatUint(m.TxPackets, 10))
	offset += copy(b[offset:], "i,rx_packets=")
	offset += copy(b[offset:], strconv.FormatUint(m.RxPackets, 10))
	offset += copy(b[offset:], "i,packets=")
	offset += copy(b[offset:], strconv.FormatUint(m.TxPackets+m.RxPackets, 10))
	b[offset] = 'i'
	offset++

	return offset
}

func (m *VTAPUsageMeter) Merge(other *VTAPUsageMeter) {
	m.TxBytes += other.TxBytes
	m.RxBytes += other.RxBytes
	m.TxPackets += other.TxPackets
	m.RxPackets += other.RxPackets
}

func (m *VTAPUsageMeter) ConcurrentMerge(other app.Meter) {
	if other, ok := other.(*VTAPUsageMeter); ok {
		m.Merge(other)
	}
}

func (m *VTAPUsageMeter) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}
