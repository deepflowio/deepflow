package zerodoc

import "gitlab.x.lan/yunshan/droplet-libs/app"

type UsageMeter struct {
	UsageMeterSum
	UsageMeterMax
}

func (m *UsageMeter) ConcurrentMerge(other app.Meter) {
	if um, ok := other.(*UsageMeter); ok {
		m.UsageMeterSum.concurrentMerge(&um.UsageMeterSum)
		m.UsageMeterMax.concurrentMerge(&um.UsageMeterMax)
	}
}

func (m *UsageMeter) SequentialMerge(other app.Meter) {
	if um, ok := other.(*UsageMeter); ok {
		m.UsageMeterSum.sequentialMerge(&um.UsageMeterSum)
		m.UsageMeterMax.sequentialMerge(&um.UsageMeterMax)
	}
}

func (m *UsageMeter) ToMap() map[string]interface{} {
	um := make(map[string]interface{})
	//usageMeterSum
	m.UsageMeterSum.ToMap(um)

	//usageMeterMax
	m.UsageMeterMax.ToMap(um)

	return um
}

type UsageMeterSum struct {
	SumPacketTx uint64
	SumPacketRx uint64
	SumPacket   uint64
	SumBitTx    uint64
	SumBitRx    uint64
	SumBit      uint64
}

func (m *UsageMeterSum) ToMap(sm map[string]interface{}) {
	sm["sum_packet_tx"] = int64(m.SumPacketTx)
	sm["sum_packet_rx"] = int64(m.SumPacketRx)
	sm["sum_packet"] = int64(m.SumPacket)
	sm["sum_bit_tx"] = int64(m.SumBitTx)
	sm["sum_bit_rx"] = int64(m.SumBitRx)
	sm["sum_bit"] = int64(m.SumBit)
}

func (m *UsageMeterSum) concurrentMerge(other *UsageMeterSum) {
	m.SumPacketTx += other.SumPacketTx
	m.SumPacketRx += other.SumPacketRx
	m.SumPacket += other.SumPacket
	m.SumBitTx += other.SumBitTx
	m.SumBitRx += other.SumBitRx
	m.SumBit += other.SumBit
}

func (m *UsageMeterSum) sequentialMerge(other *UsageMeterSum) {
	m.concurrentMerge(other)
}

type UsageMeterMax struct {
	MaxPacketTx uint64
	MaxPacketRx uint64
	MaxPacket   uint64
	MaxBitTx    uint64
	MaxBitRx    uint64
	MaxBit      uint64
}

func (m *UsageMeterMax) ToMap(mm map[string]interface{}) {
	mm["max_packet_tx"] = int64(m.MaxPacketTx)
	mm["max_packet_rx"] = int64(m.MaxPacketRx)
	mm["max_packet"] = int64(m.MaxPacket)
	mm["max_bit_tx"] = int64(m.MaxBitTx)
	mm["max_bit_rx"] = int64(m.MaxBitRx)
	mm["max_bit"] = int64(m.MaxBit)
}

func (m *UsageMeterMax) concurrentMerge(other *UsageMeterMax) {
	m.MaxPacketTx += other.MaxPacketTx
	m.MaxPacketRx += other.MaxPacketRx
	m.MaxPacket += other.MaxPacket
	m.MaxBitTx += other.MaxBitTx
	m.MaxBitRx += other.MaxBitRx
	m.MaxBit += other.MaxBit
}

func (m *UsageMeterMax) sequentialMerge(other *UsageMeterMax) {
	m.MaxPacketTx = maxU64(m.MaxPacketTx, other.MaxPacketTx)
	m.MaxPacketRx = maxU64(m.MaxPacketRx, other.MaxPacketRx)
	m.MaxPacket = maxU64(m.MaxPacket, other.MaxPacket)
	m.MaxBitTx = maxU64(m.MaxBitTx, other.MaxBitTx)
	m.MaxBitRx = maxU64(m.MaxBitRx, other.MaxBitRx)
	m.MaxBit = maxU64(m.MaxBit, other.MaxBit)
}
