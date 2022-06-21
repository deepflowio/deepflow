package zerodoc

import (
	"gitlab.yunshan.net/yunshan/droplet-libs/ckdb"
	"gitlab.yunshan.net/yunshan/droplet-libs/zerodoc/pb"
)

type FlowMeter struct {
	Traffic
	Latency
	Performance
	Anomaly
	FlowLoad
}

func (m *FlowMeter) Reverse() {
	m.Traffic.Reverse()
	m.Latency.Reverse()
	m.Performance.Reverse()
	m.Anomaly.Reverse()
	m.FlowLoad.Reverse()
}

func (m *FlowMeter) ID() uint8 {
	return FLOW_ID
}

func (m *FlowMeter) Name() string {
	return MeterVTAPNames[m.ID()]
}

func (m *FlowMeter) VTAPName() string {
	return MeterVTAPNames[m.ID()]
}

func (m *FlowMeter) SortKey() uint64 {
	return m.PacketTx + m.PacketRx
}

func (m *FlowMeter) WriteToPB(p *pb.FlowMeter) {
	if p.Traffic == nil {
		p.Traffic = &pb.Traffic{}
	}
	m.Traffic.WriteToPB(p.Traffic)

	if p.Latency == nil {
		p.Latency = &pb.Latency{}
	}
	m.Latency.WriteToPB(p.Latency)

	if p.Performance == nil {
		p.Performance = &pb.Performance{}
	}
	m.Performance.WriteToPB(p.Performance)

	if p.Anomaly == nil {
		p.Anomaly = &pb.Anomaly{}
	}
	m.Anomaly.WriteToPB(p.Anomaly)

	if p.Flowload == nil {
		p.Flowload = &pb.FlowLoad{}
	}
	m.FlowLoad.WriteToPB(p.Flowload)
}

func (m *FlowMeter) ReadFromPB(p *pb.FlowMeter) {
	m.Traffic.ReadFromPB(p.Traffic)
	m.Latency.ReadFromPB(p.Latency)
	m.Performance.ReadFromPB(p.Performance)
	m.Anomaly.ReadFromPB(p.Anomaly)
	m.FlowLoad.ReadFromPB(p.Flowload)
}

func (m *FlowMeter) ConcurrentMerge(other Meter) {
	if pm, ok := other.(*FlowMeter); ok {
		m.Traffic.ConcurrentMerge(&pm.Traffic)
		m.Latency.ConcurrentMerge(&pm.Latency)
		m.Performance.ConcurrentMerge(&pm.Performance)
		m.Anomaly.ConcurrentMerge(&pm.Anomaly)
		m.FlowLoad.ConcurrentMerge(&pm.FlowLoad)
	}
}

func (m *FlowMeter) SequentialMerge(other Meter) {
	if pm, ok := other.(*FlowMeter); ok {
		m.Traffic.SequentialMerge(&pm.Traffic)
		m.Latency.SequentialMerge(&pm.Latency)
		m.Performance.SequentialMerge(&pm.Performance)
		m.Anomaly.SequentialMerge(&pm.Anomaly)
		m.FlowLoad.SequentialMerge(&pm.FlowLoad)
	}
}

func (m *FlowMeter) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *FlowMeter) MarshalTo(b []byte) int {
	offset := 0

	offset += m.Traffic.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}
	offset += m.Latency.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}
	offset += m.Performance.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}
	offset += m.Anomaly.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}
	offset += m.FlowLoad.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] == ',' {
		offset--
	}

	return offset
}

func FlowMeterColumns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	columns = append(columns, TrafficColumns()...)
	columns = append(columns, LatencyColumns()...)
	columns = append(columns, PerformanceColumns()...)
	columns = append(columns, AnomalyColumns()...)
	columns = append(columns, FlowLoadColumns()...)
	return columns
}

func (m *FlowMeter) WriteBlock(block *ckdb.Block) error {
	if err := m.Traffic.WriteBlock(block); err != nil {
		return err
	}
	if err := m.Latency.WriteBlock(block); err != nil {
		return err
	}
	if err := m.Performance.WriteBlock(block); err != nil {
		return err
	}
	if err := m.Anomaly.WriteBlock(block); err != nil {
		return err
	}
	if err := m.FlowLoad.WriteBlock(block); err != nil {
		return err
	}

	return nil
}
