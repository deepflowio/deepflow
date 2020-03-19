package zerodoc

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type VTAPUsageMeter struct {
	PacketTx uint64 `db:"packet_tx"`
	PacketRx uint64 `db:"packet_rx"`
	ByteTx   uint64 `db:"byte_tx"`
	ByteRx   uint64 `db:"byte_rx"`
}

func (m *VTAPUsageMeter) Reverse() {
	m.PacketTx, m.PacketRx = m.PacketRx, m.PacketTx
	m.ByteTx, m.ByteRx = m.ByteRx, m.ByteTx
}

func (m *VTAPUsageMeter) ID() uint8 {
	return VTAP_USAGE_ID
}

func (m *VTAPUsageMeter) Name() string {
	return MeterVTAPNames[m.ID()]
}

func (m *VTAPUsageMeter) VTAPName() string {
	return MeterVTAPNames[m.ID()]
}

func (m *VTAPUsageMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.PacketTx)
	encoder.WriteVarintU64(m.PacketRx)
	encoder.WriteVarintU64(m.ByteTx)
	encoder.WriteVarintU64(m.ByteRx)
}

func (m *VTAPUsageMeter) Decode(decoder *codec.SimpleDecoder) {
	m.PacketTx = decoder.ReadVarintU64()
	m.PacketRx = decoder.ReadVarintU64()
	m.ByteTx = decoder.ReadVarintU64()
	m.ByteRx = decoder.ReadVarintU64()
}

func (m *VTAPUsageMeter) SortKey() uint64 {
	return uint64(m.ByteTx) + uint64(m.ByteRx)
}

func (m *VTAPUsageMeter) ToKVString() string {
	buffer := make([]byte, app.MAX_DOC_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *VTAPUsageMeter) MarshalTo(b []byte) int {
	offset := 0
	offset += copy(b[offset:], "packet_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.PacketTx, 10))
	offset += copy(b[offset:], "i,packet_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.PacketRx, 10))
	offset += copy(b[offset:], "i,byte_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.ByteTx, 10))
	offset += copy(b[offset:], "i,byte_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.ByteRx, 10))
	b[offset] = 'i'
	offset++

	return offset
}

func (m *VTAPUsageMeter) Merge(other *VTAPUsageMeter) {
	m.PacketTx += other.PacketTx
	m.PacketRx += other.PacketRx
	m.ByteTx += other.ByteTx
	m.ByteRx += other.ByteRx
}

func (m *VTAPUsageMeter) ConcurrentMerge(other app.Meter) {
	if other, ok := other.(*VTAPUsageMeter); ok {
		m.Merge(other)
	}
}

func (m *VTAPUsageMeter) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}

func (m *VTAPUsageMeter) Fill(ids []uint8, values []interface{}) {
	for i, id := range ids {
		if id <= _METER_INVALID_ || id >= _METER_MAX_ID_ || values[i] == nil {
			continue
		}
		switch id {
		case _METER_PACKET_TX:
			m.PacketTx = uint64(values[i].(int64))
		case _METER_PACKET_RX:
			m.PacketRx = uint64(values[i].(int64))
		case _METER_BYTE_TX:
			m.ByteTx = uint64(values[i].(int64))
		case _METER_BYTE_RX:
			m.ByteRx = uint64(values[i].(int64))
		default:
			log.Warningf("unsupport meter id=%d", id)
		}
	}
}
