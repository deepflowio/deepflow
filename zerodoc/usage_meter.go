package zerodoc

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type UsageMeter struct {
	SumPacketTx uint64 `db:"sum_packet_tx"`
	SumPacketRx uint64 `db:"sum_packet_rx"`
	SumBitTx    uint64 `db:"sum_bit_tx"`
	SumBitRx    uint64 `db:"sum_bit_rx"`
}

func (m *UsageMeter) SortKey() uint64 {
	return m.SumPacketTx + m.SumPacketRx
}

func (m *UsageMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.SumPacketTx)
	encoder.WriteVarintU64(m.SumPacketRx)
	encoder.WriteVarintU64(m.SumBitTx)
	encoder.WriteVarintU64(m.SumBitRx)
}

func (m *UsageMeter) Decode(decoder *codec.SimpleDecoder) {
	m.SumPacketTx = decoder.ReadVarintU64()
	m.SumPacketRx = decoder.ReadVarintU64()
	m.SumBitTx = decoder.ReadVarintU64()
	m.SumBitRx = decoder.ReadVarintU64()
}

func (m *UsageMeter) ConcurrentMerge(other app.Meter) {
	if um, ok := other.(*UsageMeter); ok {
		m.SumPacketTx += um.SumPacketTx
		m.SumPacketRx += um.SumPacketRx
		m.SumBitTx += um.SumBitTx
		m.SumBitRx += um.SumBitRx
	}
}

func (m *UsageMeter) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}

func (m *UsageMeter) ToKVString() string {
	buffer := make([]byte, app.MAX_DOC_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *UsageMeter) MarshalTo(b []byte) int {
	offset := 0

	offset += copy(b[offset:], "sum_packet_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumPacketTx, 10))
	offset += copy(b[offset:], "i,sum_packet_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumPacketRx, 10))
	offset += copy(b[offset:], "i,sum_packet=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumPacketTx+m.SumPacketRx, 10))
	offset += copy(b[offset:], "i,sum_bit_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumBitTx, 10))
	offset += copy(b[offset:], "i,sum_bit_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumBitRx, 10))
	offset += copy(b[offset:], "i,sum_bit=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumBitTx+m.SumBitRx, 10))
	b[offset] = 'i'
	offset++

	return offset
}

func (m *UsageMeter) Fill(isTag []bool, names []string, values []interface{}) {
	for i, name := range names {
		if isTag[i] || values[i] == nil {
			continue
		}
		switch name {
		case "sum_packet_tx":
			m.SumPacketTx = uint64(values[i].(int64))
		case "sum_packet_rx":
			m.SumPacketRx = uint64(values[i].(int64))
		case "sum_bit_tx":
			m.SumBitTx = uint64(values[i].(int64))
		case "sum_bit_rx":
			m.SumBitRx = uint64(values[i].(int64))
		}
	}
}
