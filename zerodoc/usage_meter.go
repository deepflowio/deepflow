package zerodoc

import (
	"strconv"

	"gitlab.yunshan.net/yunshan/droplet-libs/app"
	"gitlab.yunshan.net/yunshan/droplet-libs/ckdb"
	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
)

type UsageMeter struct {
	PacketTx uint64 `db:"packet_tx"`
	PacketRx uint64 `db:"packet_rx"`
	ByteTx   uint64 `db:"byte_tx"`
	ByteRx   uint64 `db:"byte_rx"`
	L3ByteTx uint64 `db:"l3_byte_tx"`
	L3ByteRx uint64 `db:"l3_byte_rx"`
	L4ByteTx uint64 `db:"l4_byte_tx"`
	L4ByteRx uint64 `db:"l4_byte_rx"`
}

func (m *UsageMeter) Reverse() {
	m.PacketTx, m.PacketRx = m.PacketRx, m.PacketTx
	m.ByteTx, m.ByteRx = m.ByteRx, m.ByteTx
	m.L3ByteTx, m.L3ByteRx = m.L3ByteRx, m.L3ByteTx
	m.L4ByteTx, m.L4ByteRx = m.L4ByteRx, m.L4ByteTx
}

func (m *UsageMeter) ID() uint8 {
	return PACKET_ID
}

func (m *UsageMeter) Name() string {
	return MeterVTAPNames[m.ID()]
}

func (m *UsageMeter) VTAPName() string {
	return MeterVTAPNames[m.ID()]
}

func (m *UsageMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.PacketTx)
	encoder.WriteVarintU64(m.PacketRx)
	encoder.WriteVarintU64(m.ByteTx)
	encoder.WriteVarintU64(m.ByteRx)
	encoder.WriteVarintU64(m.L3ByteTx)
	encoder.WriteVarintU64(m.L3ByteRx)
	encoder.WriteVarintU64(m.L4ByteTx)
	encoder.WriteVarintU64(m.L4ByteRx)
}

func (m *UsageMeter) Decode(decoder *codec.SimpleDecoder) {
	m.PacketTx = decoder.ReadVarintU64()
	m.PacketRx = decoder.ReadVarintU64()
	m.ByteTx = decoder.ReadVarintU64()
	m.ByteRx = decoder.ReadVarintU64()
	m.L3ByteTx = decoder.ReadVarintU64()
	m.L3ByteRx = decoder.ReadVarintU64()
	m.L4ByteTx = decoder.ReadVarintU64()
	m.L4ByteRx = decoder.ReadVarintU64()
}

func (m *UsageMeter) SortKey() uint64 {
	return uint64(m.ByteTx) + uint64(m.ByteRx)
}

func (m *UsageMeter) ToKVString() string {
	buffer := make([]byte, app.MAX_DOC_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *UsageMeter) MarshalTo(b []byte) int {
	offset := 0
	offset += copy(b[offset:], "packet_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.PacketTx, 10))
	offset += copy(b[offset:], "i,packet_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.PacketRx, 10))
	offset += copy(b[offset:], "i,packet=")
	offset += copy(b[offset:], strconv.FormatUint(m.PacketTx+m.PacketRx, 10))
	offset += copy(b[offset:], "i,byte_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.ByteTx, 10))
	offset += copy(b[offset:], "i,byte_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.ByteRx, 10))
	offset += copy(b[offset:], "i,byte=")
	offset += copy(b[offset:], strconv.FormatUint(m.ByteTx+m.ByteRx, 10))
	offset += copy(b[offset:], "i,l3_byte_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.L3ByteTx, 10))
	offset += copy(b[offset:], "i,l3_byte_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.L3ByteRx, 10))
	offset += copy(b[offset:], "i,l4_byte_tx=")
	offset += copy(b[offset:], strconv.FormatUint(m.L4ByteTx, 10))
	offset += copy(b[offset:], "i,l4_byte_rx=")
	offset += copy(b[offset:], strconv.FormatUint(m.L4ByteRx, 10))
	b[offset] = 'i'
	offset++

	return offset
}

const (
	USAGE_PACKET_TX = iota
	USAGE_PACKET_RX
	USAGE_PACKET

	USAGE_BYTE_TX
	USAGE_BYTE_RX
	USAGE_BYTE

	USAGE_L3_BYTE_TX
	USAGE_L3_BYTE_RX
	USAGE_L4_BYTE_TX
	USAGE_L4_BYTE_RX
)

// Columns列和WriteBlock的列需要一一对应
func UsageMeterColumns() []*ckdb.Column {
	return ckdb.NewColumnsWithComment(
		[][2]string{
			USAGE_PACKET_TX: {"packet_tx", "累计发送总包数"},
			USAGE_PACKET_RX: {"packet_rx", "累计接收总包数"},
			USAGE_PACKET:    {"packet", "累计总包数"},

			USAGE_BYTE_TX: {"byte_tx", "累计发送总字节数"},
			USAGE_BYTE_RX: {"byte_rx", "累计接收总字节数"},
			USAGE_BYTE:    {"byte", "累计总字节数"},

			USAGE_L3_BYTE_TX: {"l3_byte_tx", "累计发送网络层负载总字节数"},
			USAGE_L3_BYTE_RX: {"l3_byte_rx", "累计接收网络层负载总字节数"},
			USAGE_L4_BYTE_TX: {"l4_byte_tx", "累计发送应用层负载总字节数"},
			USAGE_L4_BYTE_RX: {"l4_byte_rx", "累计接收应用层负载总字节数"},
		},
		ckdb.UInt64)
}

// WriteBlock需要和Colums的列一一对应
func (m *UsageMeter) WriteBlock(block *ckdb.Block) error {
	values := []uint64{
		USAGE_PACKET_TX: m.PacketTx,
		USAGE_PACKET_RX: m.PacketRx,
		USAGE_PACKET:    m.PacketTx + m.PacketRx,

		USAGE_BYTE_TX: m.ByteTx,
		USAGE_BYTE_RX: m.ByteRx,
		USAGE_BYTE:    m.ByteTx + m.ByteRx,

		USAGE_L3_BYTE_TX: m.L3ByteTx,
		USAGE_L3_BYTE_RX: m.L3ByteRx,
		USAGE_L4_BYTE_TX: m.L4ByteTx,
		USAGE_L4_BYTE_RX: m.L4ByteRx,
	}
	for _, v := range values {
		if err := block.WriteUInt64(v); err != nil {
			return err
		}
	}
	return nil
}

func (m *UsageMeter) Merge(other *UsageMeter) {
	m.PacketTx += other.PacketTx
	m.PacketRx += other.PacketRx
	m.ByteTx += other.ByteTx
	m.ByteRx += other.ByteRx
	m.L3ByteTx += other.L3ByteTx
	m.L3ByteRx += other.L3ByteRx
	m.L4ByteTx += other.L4ByteTx
	m.L4ByteRx += other.L4ByteRx
}

func (m *UsageMeter) ConcurrentMerge(other app.Meter) {
	if other, ok := other.(*UsageMeter); ok {
		m.Merge(other)
	}
}

func (m *UsageMeter) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}
