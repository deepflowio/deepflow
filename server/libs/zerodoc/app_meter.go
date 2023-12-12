/*
 * Copyright (c) 2023 Yunshan Networks
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

package zerodoc

import (
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/zerodoc/pb"
)

type AppMeter struct {
	AppTraffic
	AppLatency
	AppAnomaly
}

func (m *AppMeter) Reverse() {
	m.AppTraffic.Reverse()
	m.AppLatency.Reverse()
	m.AppAnomaly.Reverse()
}

func (m *AppMeter) ID() uint8 {
	return APP_ID
}

func (m *AppMeter) Name() string {
	return MeterVTAPNames[m.ID()]
}

func (m *AppMeter) VTAPName() string {
	return MeterVTAPNames[m.ID()]
}

func (m *AppMeter) SortKey() uint64 {
	return m.RRTSum
}

func (m *AppMeter) WriteToPB(p *pb.AppMeter) {
	if p.Traffic == nil {
		p.Traffic = &pb.AppTraffic{}
	}
	m.AppTraffic.WriteToPB(p.Traffic)

	if p.Latency == nil {
		p.Latency = &pb.AppLatency{}
	}
	m.AppLatency.WriteToPB(p.Latency)

	if p.Anomaly == nil {
		p.Anomaly = &pb.AppAnomaly{}
	}
	m.AppAnomaly.WriteToPB(p.Anomaly)
}

func (m *AppMeter) ReadFromPB(p *pb.AppMeter) {
	m.AppTraffic.ReadFromPB(p.Traffic)
	m.AppLatency.ReadFromPB(p.Latency)
	m.AppAnomaly.ReadFromPB(p.Anomaly)
}

func (m *AppMeter) ConcurrentMerge(other Meter) {
	if pm, ok := other.(*AppMeter); ok {
		m.AppTraffic.ConcurrentMerge(&pm.AppTraffic)
		m.AppLatency.ConcurrentMerge(&pm.AppLatency)
		m.AppAnomaly.ConcurrentMerge(&pm.AppAnomaly)
	}
}

func (m *AppMeter) SequentialMerge(other Meter) {
	if pm, ok := other.(*AppMeter); ok {
		m.AppTraffic.SequentialMerge(&pm.AppTraffic)
		m.AppLatency.SequentialMerge(&pm.AppLatency)
		m.AppAnomaly.SequentialMerge(&pm.AppAnomaly)
	}
}

func (m *AppMeter) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *AppMeter) MarshalTo(b []byte) int {
	offset := 0

	offset += m.AppTraffic.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}

	offset += m.AppLatency.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}
	offset += m.AppAnomaly.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}

	return offset
}

func AppMeterColumns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	columns = append(columns, AppTrafficColumns()...)
	columns = append(columns, AppLatencyColumns()...)
	columns = append(columns, AppAnomalyColumns()...)
	return columns
}

func (m *AppMeter) WriteBlock(block *ckdb.Block) {
	m.AppTraffic.WriteBlock(block)
	m.AppLatency.WriteBlock(block)
	m.AppAnomaly.WriteBlock(block)
}

type AppTraffic struct {
	Request        uint32 `db:"request"`
	Response       uint32 `db:"response"`
	DirectionScore uint8  `db:"direction_score"`
}

func (_ *AppTraffic) Reverse() {
	// 异常统计量以客户端、服务端为视角，无需Reverse
}

func (t *AppTraffic) WriteToPB(p *pb.AppTraffic) {
	p.Request = t.Request
	p.Response = t.Response
	p.DirectionScore = uint32(t.DirectionScore)
}

func (t *AppTraffic) ReadFromPB(p *pb.AppTraffic) {
	t.Request = p.Request
	t.Response = p.Response
	t.DirectionScore = uint8(p.DirectionScore)
}

func (t *AppTraffic) ConcurrentMerge(other *AppTraffic) {
	t.Request += other.Request
	t.Response += other.Response
	if t.DirectionScore < other.DirectionScore {
		t.DirectionScore = other.DirectionScore
	}
}

func (t *AppTraffic) SequentialMerge(other *AppTraffic) {
	t.ConcurrentMerge(other)
}

func (t *AppTraffic) MarshalTo(b []byte) int {
	fields := []string{"request=", "response=", "direction_score"}
	values := []uint64{uint64(t.Request), uint64(t.Response), uint64(t.DirectionScore)}
	return marshalKeyValues(b, fields, values)
}

const (
	AppTRIFFIC_RRT_MAX = iota
	AppTRIFFIC_RRT_SUM
	AppTRIFFIC_RRT_COUNT
)

// Columns列和WriteBlock的列需要按顺序一一对应
func AppTrafficColumns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	columns = append(columns, ckdb.NewColumn("request", ckdb.UInt32).SetComment("累计请求次数"))
	columns = append(columns, ckdb.NewColumn("response", ckdb.UInt32).SetComment("累计响应次数"))
	columns = append(columns, ckdb.NewColumn("direction_score", ckdb.UInt8).SetComment("for correcting direction").SetIndex(ckdb.IndexMinmax))
	return columns
}

// WriteBlock和LatencyColumns的列需要按顺序一一对应
func (t *AppTraffic) WriteBlock(block *ckdb.Block) {
	block.Write(t.Request, t.Response, t.DirectionScore)
}

type AppLatency struct {
	RRTMax   uint32 `db:"rrt_max"` // us
	RRTSum   uint64 `db:"rrt_sum"` // us
	RRTCount uint32 `db:"rrt_count"`
}

func (_ *AppLatency) Reverse() {
	// 异常统计量以客户端、服务端为视角，无需Reverse
}

func (l *AppLatency) WriteToPB(p *pb.AppLatency) {
	p.RrtMax = l.RRTMax
	p.RrtSum = l.RRTSum
	p.RrtCount = l.RRTCount
}

func (l *AppLatency) ReadFromPB(p *pb.AppLatency) {
	l.RRTMax = p.RrtMax
	l.RRTSum = p.RrtSum
	l.RRTCount = p.RrtCount
}

func (l *AppLatency) ConcurrentMerge(other *AppLatency) {
	if l.RRTMax < other.RRTMax {
		l.RRTMax = other.RRTMax
	}
	l.RRTSum += other.RRTSum
	l.RRTCount += other.RRTCount
}

func (l *AppLatency) SequentialMerge(other *AppLatency) {
	l.ConcurrentMerge(other)
}

func (l *AppLatency) MarshalTo(b []byte) int {
	fields := []string{"rrt_sum=", "rrt_count=", "rrt_max="}
	values := []uint64{l.RRTSum, uint64(l.RRTCount), uint64(l.RRTMax)}
	return marshalKeyValues(b, fields, values)
}

const (
	APPLATENCY_RRT_MAX = iota
	APPLATENCY_RRT_SUM
	APPLATENCY_RRT_COUNT
)

// Columns列和WriteBlock的列需要按顺序一一对应
func AppLatencyColumns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	columns = append(columns, ckdb.NewColumn("rrt_max", ckdb.UInt32).SetComment("所有请求响应时延最大值(us)"))
	columns = append(columns, ckdb.NewColumn("rrt_sum", ckdb.Float64).SetComment("累计所有请求响应时延(us)"))
	columns = append(columns, ckdb.NewColumn("rrt_count", ckdb.UInt64).SetComment("请求响应时延计算次数"))
	return columns
}

// WriteBlock和LatencyColumns的列需要按顺序一一对应
func (l *AppLatency) WriteBlock(block *ckdb.Block) {
	block.Write(l.RRTMax, float64(l.RRTSum), uint64(l.RRTCount))
}

type AppAnomaly struct {
	ClientError uint32 `db:"client_error"`
	ServerError uint32 `db:"server_error"`
	Timeout     uint32 `db:"timeout"`
}

func (_ *AppAnomaly) Reverse() {
	// 异常统计量以客户端、服务端为视角，无需Reverse
}

func (a *AppAnomaly) WriteToPB(p *pb.AppAnomaly) {
	p.ClientError = a.ClientError
	p.ServerError = a.ServerError
	p.Timeout = a.Timeout
}

func (a *AppAnomaly) ReadFromPB(p *pb.AppAnomaly) {
	a.ClientError = p.ClientError
	a.ServerError = p.ServerError
	a.Timeout = p.Timeout
}

func (a *AppAnomaly) ConcurrentMerge(other *AppAnomaly) {
	a.ClientError += other.ClientError
	a.ServerError += other.ServerError
	a.Timeout += other.Timeout
}

func (a *AppAnomaly) SequentialMerge(other *AppAnomaly) {
	a.ConcurrentMerge(other)
}

func (a *AppAnomaly) MarshalTo(b []byte) int {
	fields := []string{
		"client_error=", "server_error=", "timeout=", "error=",
	}
	values := []uint64{
		uint64(a.ClientError), uint64(a.ServerError), uint64(a.Timeout), uint64(a.ClientError + a.ServerError),
	}
	return marshalKeyValues(b, fields, values)
}

const (
	APPANOMALY_CLIENT_ERROR = iota
	APPANOMALY_SERVER_ERROR
	APPANOMALY_TIMEOUT
	APPANOMALY_ERROR
)

// Columns列和WriteBlock的列需要按顺序一一对应
func AppAnomalyColumns() []*ckdb.Column {
	columns := ckdb.NewColumnsWithComment(
		[][2]string{
			APPANOMALY_CLIENT_ERROR: {"client_error", "客户端异常次数"},
			APPANOMALY_SERVER_ERROR: {"server_error", "服务端异常次数"},
			APPANOMALY_TIMEOUT:      {"timeout", "请求超时次数"},
			APPANOMALY_ERROR:        {"error", "异常次数"},
		}, ckdb.UInt64)
	return columns
}

// WriteBlock的列和AnomalyColumns需要按顺序一一对应
func (a *AppAnomaly) WriteBlock(block *ckdb.Block) {
	block.Write(uint64(a.ClientError), uint64(a.ServerError), uint64(a.Timeout), uint64(a.ClientError+a.ServerError))
}

func EncodeAppMeterToMetrics(meter *AppMeter) map[string]float64 {
	if meter == nil {
		return nil
	}

	buffer := make([]byte, MAX_STRING_LENGTH)
	size := meter.MarshalTo(buffer)
	return encodeMeterToMetrics(buffer[:size])
}

func encodeMeterToMetrics(b []byte) map[string]float64 {
	s := string(b)
	metrics := make(map[string]float64)
	for _, part := range strings.Split(s, ",") {
		kv := strings.Split(part, "=")
		if len(kv) != 2 {
			continue
		}

		f, err := strconv.ParseFloat(strings.TrimRight(kv[1], "i"), 10)
		if err != nil {
			continue
		}
		metrics[kv[0]] = f
	}
	return metrics
}
