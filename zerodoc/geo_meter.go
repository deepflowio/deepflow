package zerodoc

import (
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type GeoMeter struct {
	SumClosedFlowCount    uint64
	SumAbnormalFlowCount  uint64
	SumClosedFlowDuration time.Duration
	SumPacketTx           uint64
	SumPacketRx           uint64
	SumBitTx              uint64
	SumBitRx              uint64
}

func (m *GeoMeter) ConcurrentMerge(other app.Meter) {
	if pgm, ok := other.(*GeoMeter); ok {
		m.SumClosedFlowCount += pgm.SumClosedFlowCount
		m.SumAbnormalFlowCount += pgm.SumAbnormalFlowCount
		m.SumClosedFlowDuration += pgm.SumClosedFlowDuration
		m.SumPacketTx += pgm.SumPacketTx
		m.SumPacketRx += pgm.SumPacketRx
		m.SumBitTx += pgm.SumBitTx
		m.SumBitRx += pgm.SumBitRx
	}
}

func (m *GeoMeter) SequentialMerge(other app.Meter) {
	if pgm, ok := other.(*GeoMeter); ok {
		m.SumClosedFlowCount += pgm.SumClosedFlowCount
		m.SumAbnormalFlowCount += pgm.SumAbnormalFlowCount
		m.SumClosedFlowDuration += pgm.SumClosedFlowDuration
		m.SumPacketTx += pgm.SumPacketTx
		m.SumPacketRx += pgm.SumPacketRx
		m.SumBitTx += pgm.SumBitTx
		m.SumBitRx += pgm.SumBitRx
	}
}

func (m *GeoMeter) ToMap() map[string]interface{} {
	pgm := make(map[string]interface{})
	pgm["sum_closed_flow_count"] = int64(m.SumClosedFlowCount)
	pgm["sum_abnormal_flow_count"] = int64(m.SumAbnormalFlowCount)
	pgm["sum_closed_flow_duration"] = int64(m.SumClosedFlowDuration / time.Microsecond)
	pgm["sum_packet_tx"] = int64(m.SumPacketTx)
	pgm["sum_packet_rx"] = int64(m.SumPacketRx)
	pgm["sum_bit_tx"] = int64(m.SumBitTx)
	pgm["sum_bit_rx"] = int64(m.SumBitRx)
	return pgm
}
