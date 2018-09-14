package zerodoc

import (
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
)

type ConsoleLogMeter struct {
	SumPacketTx           uint64
	SumPacketRx           uint64
	SumClosedFlowCount    uint64
	SumClosedFlowDuration time.Duration
}

func (m *ConsoleLogMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*ConsoleLogMeter); ok {
		m.SumPacketTx += pm.SumPacketTx
		m.SumPacketRx += pm.SumPacketRx
		m.SumClosedFlowCount += pm.SumClosedFlowCount
		m.SumClosedFlowDuration += pm.SumClosedFlowDuration
	}
}

func (m *ConsoleLogMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*ConsoleLogMeter); ok {
		m.SumPacketTx += pm.SumPacketTx
		m.SumPacketRx += pm.SumPacketRx
		m.SumClosedFlowCount += pm.SumClosedFlowCount
		m.SumClosedFlowDuration += pm.SumClosedFlowDuration
	}
}

func (m *ConsoleLogMeter) ToMap() map[string]interface{} {
	pm := make(map[string]interface{})
	pm["sum_packet_tx"] = int64(m.SumPacketTx)
	pm["sum_packet_rx"] = int64(m.SumPacketRx)
	pm["sum_closed_flow_count"] = int64(m.SumClosedFlowCount)
	pm["sum_closed_flow_duration"] = int64(m.SumClosedFlowDuration / time.Microsecond)
	return pm
}
