package zerodoc

import "gitlab.x.lan/yunshan/droplet-libs/app"

type PlatformMeter struct {
	SumClosedFlowCount uint64
	SumPacket          uint64
	SumBit             uint64
}

func (m *PlatformMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*PlatformMeter); ok {
		m.SumClosedFlowCount += pm.SumClosedFlowCount
		m.SumPacket += pm.SumPacket
		m.SumBit += pm.SumBit
	}
}

func (m *PlatformMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*PlatformMeter); ok {
		m.SumClosedFlowCount += pm.SumClosedFlowCount
		m.SumPacket += pm.SumPacket
		m.SumBit += pm.SumBit
	}
}

func (m *PlatformMeter) ToMap() map[string]interface{} {
	pm := make(map[string]interface{})
	pm["sum_closed_flow_count"] = int64(m.SumClosedFlowCount)
	pm["sum_packet"] = int64(m.SumPacket)
	pm["sum_bit"] = int64(m.SumBit)
	return pm
}
