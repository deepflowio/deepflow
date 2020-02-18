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

func (m *VTAPSimpleMeter) Reverse() {
	m.TxBytes, m.RxBytes = m.RxBytes, m.TxBytes
	m.TxPackets, m.RxPackets = m.RxPackets, m.TxPackets
}

func (m *VTAPSimpleMeter) ID() uint8 {
	return VTAP_SIMPLE_ID
}

func (m *VTAPSimpleMeter) Name() string {
	return MeterDFNames[VTAP_SIMPLE_ID]
}

func (m *VTAPSimpleMeter) VTAPName() string {
	return MeterVTAPNames[VTAP_SIMPLE_ID]
}

func (m *VTAPSimpleMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.TxBytes)
	encoder.WriteVarintU64(m.RxBytes)
	encoder.WriteVarintU64(m.Bytes)
	encoder.WriteVarintU64(m.TxPackets)
	encoder.WriteVarintU64(m.RxPackets)
	encoder.WriteVarintU64(m.Packets)
}

func (m *VTAPSimpleMeter) Decode(decoder *codec.SimpleDecoder) {
	m.TxBytes = decoder.ReadVarintU64()
	m.RxBytes = decoder.ReadVarintU64()
	m.Bytes = decoder.ReadVarintU64()
	m.TxPackets = decoder.ReadVarintU64()
	m.RxPackets = decoder.ReadVarintU64()
	m.Packets = decoder.ReadVarintU64()
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

func (m *VTAPSimpleMeter) Fill(ids []uint8, values []interface{}) {
	for i, id := range ids {
		if id <= _METER_INVALID_ || id >= _METER_MAX_ID_ || values[i] == nil {
			continue
		}
		switch id {
		case _METER_TX_BYTES:
			m.TxBytes = uint64(values[i].(int64))
		case _METER_RX_BYTES:
			m.RxBytes = uint64(values[i].(int64))
		case _METER_BYTES:
			m.Bytes = uint64(values[i].(int64))
		case _METER_TX_PACKETS:
			m.TxPackets = uint64(values[i].(int64))
		case _METER_RX_PACKETS:
			m.RxPackets = uint64(values[i].(int64))
		case _METER_PACKETS:
			m.Packets = uint64(values[i].(int64))
		default:
			log.Warningf("unsupport meter id=%d", id)
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
