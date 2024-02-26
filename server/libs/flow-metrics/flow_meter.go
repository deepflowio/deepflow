/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package flow_metrics

import (
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
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

	if p.FlowLoad == nil {
		p.FlowLoad = &pb.FlowLoad{}
	}
	m.FlowLoad.WriteToPB(p.FlowLoad)
}

func (m *FlowMeter) ReadFromPB(p *pb.FlowMeter) {
	m.Traffic.ReadFromPB(p.Traffic)
	m.Latency.ReadFromPB(p.Latency)
	m.Performance.ReadFromPB(p.Performance)
	m.Anomaly.ReadFromPB(p.Anomaly)
	m.FlowLoad.ReadFromPB(p.FlowLoad)
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

func (m *FlowMeter) WriteBlock(block *ckdb.Block) {
	m.Traffic.WriteBlock(block)
	m.Latency.WriteBlock(block)
	m.Performance.WriteBlock(block)
	m.Anomaly.WriteBlock(block)
	m.FlowLoad.WriteBlock(block)
}
