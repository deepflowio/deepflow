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
	"strconv"

	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
)

type Traffic struct {
	PacketTx   uint64 `json:"packet_tx" category:"$metrics" sub:"l3_throughput"`
	PacketRx   uint64 `json:"packet_rx" category:"$metrics" sub:"l3_throughput"`
	ByteTx     uint64 `json:"byte_tx" category:"$metrics" sub:"l3_throughput"`
	ByteRx     uint64 `json:"byte_rx" category:"$metrics" sub:"l3_throughput"`
	L3ByteTx   uint64 `json:"l3_byte_tx" category:"$metrics" sub:"l3_throughput"`
	L3ByteRx   uint64 `json:"l3_byte_rx" category:"$metrics" sub:"l3_throughput"`
	L4ByteTx   uint64 `json:"l4_byte_tx" category:"$metrics" sub:"l4_throughput"`
	L4ByteRx   uint64 `json:"l4_byte_rx" category:"$metrics" sub:"l4_throughput"`
	NewFlow    uint64 `json:"new_flow" category:"$metrics" sub:"l4_throughput"`
	ClosedFlow uint64 `json:"closed_flow" category:"$metrics" sub:"l4_throughput"`

	L7Request   uint32 `json:"l7_request" category:"$metrics" sub:"application"`
	L7Response  uint32 `json:"l7_response" category:"$metrics" sub:"application"`
	SynCount    uint32 `json:"syn_count" category:"$metrics" sub:"l4_throughput"`
	SynackCount uint32 `json:"synack_count" category:"$metrics" sub:"l4_throughput"`

	DirectionScore uint8 `json:"direction_score" category:"$metrics" sub:"l4_throughput"`
}

func (t *Traffic) Reverse() {
	t.PacketTx, t.PacketRx = t.PacketRx, t.PacketTx
	t.ByteTx, t.ByteRx = t.ByteRx, t.ByteTx
	t.L3ByteTx, t.L3ByteRx = t.L3ByteRx, t.L3ByteTx
	t.L4ByteTx, t.L4ByteRx = t.L4ByteRx, t.L4ByteTx

	// HTTP、DNS统计量以客户端、服务端为视角，无需Reverse
}

func (t *Traffic) WriteToPB(p *pb.Traffic) {
	p.PacketTx = t.PacketTx
	p.PacketRx = t.PacketRx
	p.ByteTx = t.ByteTx
	p.ByteRx = t.ByteRx
	p.L3ByteTx = t.L3ByteTx
	p.L3ByteRx = t.L3ByteRx
	p.L4ByteTx = t.L4ByteTx
	p.L4ByteRx = t.L4ByteRx
	p.NewFlow = t.NewFlow
	p.ClosedFlow = t.ClosedFlow

	p.L7Request = t.L7Request
	p.L7Response = t.L7Response
	p.Syn = t.SynCount
	p.Synack = t.SynackCount

	p.DirectionScore = uint32(t.DirectionScore)
}

func (t *Traffic) ReadFromPB(p *pb.Traffic) {
	t.PacketTx = p.PacketTx
	t.PacketRx = p.PacketRx
	t.ByteTx = p.ByteTx
	t.ByteRx = p.ByteRx
	t.L3ByteTx = p.L3ByteTx
	t.L3ByteRx = p.L3ByteRx
	t.L4ByteTx = p.L4ByteTx
	t.L4ByteRx = p.L4ByteRx
	t.NewFlow = p.NewFlow
	t.ClosedFlow = p.ClosedFlow

	t.L7Request = p.L7Request
	t.L7Response = p.L7Response
	t.SynCount = p.Syn
	t.SynackCount = p.Synack
	t.DirectionScore = uint8(p.DirectionScore)
}

func (t *Traffic) ConcurrentMerge(other *Traffic) {
	t.PacketTx += other.PacketTx
	t.PacketRx += other.PacketRx
	t.ByteTx += other.ByteTx
	t.ByteRx += other.ByteRx
	t.L3ByteTx += other.L3ByteTx
	t.L3ByteRx += other.L3ByteRx
	t.L4ByteTx += other.L4ByteTx
	t.L4ByteRx += other.L4ByteRx
	t.NewFlow += other.NewFlow
	t.ClosedFlow += other.ClosedFlow

	t.L7Request += other.L7Request
	t.L7Response += other.L7Response
	t.SynCount += other.SynCount
	t.SynackCount += other.SynackCount
	if t.DirectionScore < other.DirectionScore {
		t.DirectionScore = other.DirectionScore
	}
}

func (t *Traffic) SequentialMerge(other *Traffic) {
	t.ConcurrentMerge(other)
}

func (t *Traffic) MarshalTo(b []byte) int {
	// 保证packet一定会写入，用于查询时，若只查tag不查field，则需要默认查询field 'packet'
	offset := 0
	offset += copy(b[offset:], "packet=")
	offset += copy(b[offset:], strconv.FormatUint(t.PacketTx+t.PacketRx, 10))
	offset += copy(b[offset:], "i,") // 先加',',若后续若没有增加数据，需要去除

	fields := []string{
		"packet_tx=", "packet_rx=", "byte_tx=", "byte_rx=", "byte=", "l3_byte_tx=", "l3_byte_rx=", "l4_byte_tx=", "l4_byte_rx=", "new_flow=", "closed_flow=",
		"l7_request=", "l7_response=", "syn_count=", "synack_count=", "direction_score=",
	}
	values := []uint64{
		t.PacketTx, t.PacketRx, t.ByteTx, t.ByteRx, t.ByteTx + t.ByteRx, t.L3ByteTx, t.L3ByteRx, t.L4ByteTx, t.L4ByteRx, t.NewFlow, t.ClosedFlow,
		uint64(t.L7Request), uint64(t.L7Response), uint64(t.SynCount), uint64(t.SynackCount), uint64(t.DirectionScore),
	}
	n := marshalKeyValues(b[offset:], fields, values)
	if n == 0 {
		offset-- // 去除','
	}
	return offset + n
}

const (
	TRAFFIC_PACKET_TX = iota
	TRAFFIC_PACKET_RX
	TRAFFIC_PACKET

	TRAFFIC_BYTE_TX
	TRAFFIC_BYTE_RX
	TRAFFIC_BYTE

	TRAFFIC_L3_BYTE_TX
	TRAFFIC_L3_BYTE_RX
	TRAFFIC_L4_BYTE_TX
	TRAFFIC_L4_BYTE_RX

	TRAFFIC_NEW_FLOW
	TRAFFIC_CLOSED_FLOW

	TRAFFIC_L7_REQUEST
	TRAFFIC_L7_RESPONSE

	TRAFFIC_SYN_COUNT
	TRAFFIC_SYNACK_COUNT
)

// Columns列和WriteBlock的列需要按顺序一一对应
func TrafficColumns() []*ckdb.Column {
	columns := ckdb.NewColumnsWithComment(
		[][2]string{
			TRAFFIC_PACKET_TX: {"packet_tx", "累计发送总包数"},
			TRAFFIC_PACKET_RX: {"packet_rx", "累计接收总包数"},
			TRAFFIC_PACKET:    {"packet", "累计总包数"},

			TRAFFIC_BYTE_TX: {"byte_tx", "累计发送总字节数"},
			TRAFFIC_BYTE_RX: {"byte_rx", "累计接收总字节数"},
			TRAFFIC_BYTE:    {"byte", "累计总字节数"},

			TRAFFIC_L3_BYTE_TX: {"l3_byte_tx", "累计发送网络层负载总字节数"},
			TRAFFIC_L3_BYTE_RX: {"l3_byte_rx", "累计接收网络层负载总字节数"},
			TRAFFIC_L4_BYTE_TX: {"l4_byte_tx", "累计发送应用层负载总字节数"},
			TRAFFIC_L4_BYTE_RX: {"l4_byte_rx", "累计接收应用层负载总字节数"},

			TRAFFIC_NEW_FLOW:    {"new_flow", "累计新建连接数"},
			TRAFFIC_CLOSED_FLOW: {"closed_flow", "累计关闭连接数"},

			TRAFFIC_L7_REQUEST:  {"l7_request", "累计应用请求数"},
			TRAFFIC_L7_RESPONSE: {"l7_response", "累计应用响应数"},

			TRAFFIC_SYN_COUNT:    {"syn_count", "Total SYN packet count"},
			TRAFFIC_SYNACK_COUNT: {"synack_count", "Total SYNACK packet count"},
		},
		ckdb.UInt64)
	columns = append(columns, ckdb.NewColumn("direction_score", ckdb.UInt8).SetIndex(ckdb.IndexMinmax))
	return columns
}

// WriteBlock的列需和Columns 按顺序一一对应
func (t *Traffic) WriteBlock(block *ckdb.Block) {
	block.Write(
		t.PacketTx,
		t.PacketRx,
		t.PacketTx+t.PacketRx,

		t.ByteTx,
		t.ByteRx,
		t.ByteTx+t.ByteRx,

		t.L3ByteTx,
		t.L3ByteRx,
		t.L4ByteTx,
		t.L4ByteRx,

		t.NewFlow,
		t.ClosedFlow,
		uint64(t.L7Request),
		uint64(t.L7Response),

		uint64(t.SynCount),
		uint64(t.SynackCount),
		t.DirectionScore,
	)
}

type Latency struct {
	RTTMax       uint32 `json:"rtt_max" category:"$metrics" sub:"delay"`        // us，Trident保证时延最大值不会超过3600s，能容纳在u32内
	RTTClientMax uint32 `json:"rtt_client_max" category:"$metrics" sub:"delay"` // us
	RTTServerMax uint32 `json:"rtt_server_max" category:"$metrics" sub:"delay"` // us
	SRTMax       uint32 `json:"srt_max" category:"$metrics" sub:"delay"`        // us
	ARTMax       uint32 `json:"art_max" category:"$metrics" sub:"delay"`        // us
	RRTMax       uint32 `json:"rrt_max" category:"$metrics" sub:"delay"`        // us
	CITMax       uint32 `json:"cit_max" category:"$metrics" sub:"delay"`        // client idle time max

	RTTSum       uint64 `json:"rtt_sum" category:"$metrics" sub:"delay"`        // us
	RTTClientSum uint64 `json:"rtt_client_sum" category:"$metrics" sub:"delay"` // us
	RTTServerSum uint64 `json:"rtt_server_sum" category:"$metrics" sub:"delay"` // us
	SRTSum       uint64 `json:"srt_sum" category:"$metrics" sub:"delay"`        // us
	ARTSum       uint64 `json:"art_sum" category:"$metrics" sub:"delay"`        // us
	RRTSum       uint64 `json:"rrt_sum" category:"$metrics" sub:"delay"`        // us
	CITSum       uint64 `json:"cit_sum" category:"$metrics" sub:"delay"`

	RTTCount       uint32 `json:"rtt_count" category:"$metrics" sub:"delay"`
	RTTClientCount uint32 `json:"rtt_client_count" category:"$metrics" sub:"delay"`
	RTTServerCount uint32 `json:"rtt_server_count" category:"$metrics" sub:"delay"`
	SRTCount       uint32 `json:"srt_count" category:"$metrics" sub:"delay"`
	ARTCount       uint32 `json:"art_count" category:"$metrics" sub:"delay"`
	RRTCount       uint32 `json:"rrt_count" category:"$metrics" sub:"delay"`
	CITCount       uint32 `json:"cit_count" category:"$metrics" sub:"delay"`
}

func (_ *Latency) Reverse() {
	// 时延统计量以客户端、服务端为视角，无需Reverse
}

func (l *Latency) WriteToPB(p *pb.Latency) {
	p.RttMax = l.RTTMax
	p.RttClientMax = l.RTTClientMax
	p.RttServerMax = l.RTTServerMax
	p.SrtMax = l.SRTMax
	p.ArtMax = l.ARTMax
	p.RrtMax = l.RRTMax
	p.CitMax = l.CITMax

	p.RttSum = l.RTTSum
	p.RttClientSum = l.RTTClientSum
	p.RttServerSum = l.RTTServerSum
	p.SrtSum = l.SRTSum
	p.ArtSum = l.ARTSum
	p.RrtSum = l.RRTSum
	p.CitSum = l.CITSum

	p.RttCount = l.RTTCount
	p.RttClientCount = l.RTTClientCount
	p.RttServerCount = l.RTTServerCount
	p.SrtCount = l.SRTCount
	p.ArtCount = l.ARTCount
	p.RrtCount = l.RRTCount
	p.CitCount = l.CITCount
}

func (l *Latency) ReadFromPB(p *pb.Latency) {
	l.RTTMax = p.RttMax
	l.RTTClientMax = p.RttClientMax
	l.RTTServerMax = p.RttServerMax
	l.SRTMax = p.SrtMax
	l.ARTMax = p.ArtMax
	l.RRTMax = p.RrtMax
	l.CITMax = p.CitMax

	l.RTTSum = p.RttSum
	l.RTTClientSum = p.RttClientSum
	l.RTTServerSum = p.RttServerSum
	l.SRTSum = p.SrtSum
	l.ARTSum = p.ArtSum
	l.RRTSum = p.RrtSum
	l.CITSum = p.CitSum

	l.RTTCount = p.RttCount
	l.RTTClientCount = p.RttClientCount
	l.RTTServerCount = p.RttServerCount
	l.SRTCount = p.SrtCount
	l.ARTCount = p.ArtCount
	l.RRTCount = p.RrtCount
	l.CITCount = p.CitCount
}

func (l *Latency) ConcurrentMerge(other *Latency) {
	if l.RTTMax < other.RTTMax {
		l.RTTMax = other.RTTMax
	}
	if l.RTTClientMax < other.RTTClientMax {
		l.RTTClientMax = other.RTTClientMax
	}
	if l.RTTServerMax < other.RTTServerMax {
		l.RTTServerMax = other.RTTServerMax
	}
	if l.SRTMax < other.SRTMax {
		l.SRTMax = other.SRTMax
	}
	if l.ARTMax < other.ARTMax {
		l.ARTMax = other.ARTMax
	}
	if l.RRTMax < other.RRTMax {
		l.RRTMax = other.RRTMax
	}
	if l.CITMax < other.CITMax {
		l.CITMax = other.CITMax
	}

	l.RTTSum += other.RTTSum
	l.RTTClientSum += other.RTTClientSum
	l.RTTServerSum += other.RTTServerSum
	l.SRTSum += other.SRTSum
	l.ARTSum += other.ARTSum
	l.RRTSum += other.RRTSum
	l.CITSum += other.CITSum

	l.RTTCount += other.RTTCount
	l.RTTClientCount += other.RTTClientCount
	l.RTTServerCount += other.RTTServerCount
	l.SRTCount += other.SRTCount
	l.ARTCount += other.ARTCount
	l.RRTCount += other.RRTCount
	l.CITCount += other.CITCount
}

func (l *Latency) SequentialMerge(other *Latency) {
	l.ConcurrentMerge(other)
}

func (l *Latency) MarshalTo(b []byte) int {
	fields := []string{"rtt_sum=", "rtt_client_sum=", "rtt_server_sum=", "srt_sum=", "art_sum=", "rrt_sum=", "cit_sum=",
		"rtt_count=", "rtt_client_count=", "rtt_server_count=", "srt_count=", "art_count=", "rrt_count=", "cit_count",
		"rtt_max=", "rtt_client_max=", "rtt_server_max=", "srt_max=", "art_max=", "rrt_max=", "cit_max="}
	values := []uint64{
		l.RTTSum, l.RTTClientSum, l.RTTServerSum, l.SRTSum, l.ARTSum, l.RRTSum, l.CITSum,
		uint64(l.RTTCount), uint64(l.RTTClientCount), uint64(l.RTTServerCount), uint64(l.SRTCount), uint64(l.ARTCount), uint64(l.RRTCount), uint64(l.CITCount),
		uint64(l.RTTMax), uint64(l.RTTClientMax), uint64(l.RTTServerMax), uint64(l.SRTMax), uint64(l.ARTMax), uint64(l.RRTMax), uint64(l.CITMax),
	}
	return marshalKeyValues(b, fields, values)
}

const (
	LATENCY_RTT = iota
	LATENCY_RTT_CLIENT
	LATENCY_RTT_SERVER
	LATENCY_SRT
	LATENCY_ART
	LATENCY_RRT
	LATENCY_CIT
)

// Columns列和WriteBlock的列需要按顺序一一对应
func LatencyColumns() []*ckdb.Column {
	sumColumns := ckdb.NewColumnsWithComment(
		[][2]string{
			LATENCY_RTT:        {"rtt_sum", "累计建立连接RTT(us)"},
			LATENCY_RTT_CLIENT: {"rtt_client_sum", "客户端累计建立连接RTT(us)"},
			LATENCY_RTT_SERVER: {"rtt_server_sum", "服务端累计建立连接RTT(us)"},
			LATENCY_SRT:        {"srt_sum", "累计所有系统响应时延(us)"},
			LATENCY_ART:        {"art_sum", "累计所有应用响应时延(us)"},
			LATENCY_RRT:        {"rrt_sum", "累计所有应用请求响应时延(us)"},
			LATENCY_CIT:        {"cit_sum", "Total client idle time(us)"},
		},
		ckdb.Float64)
	counterColumns := ckdb.NewColumnsWithComment(
		[][2]string{
			LATENCY_RTT:        {"rtt_count", "建立连接时延计算次数"},
			LATENCY_RTT_CLIENT: {"rtt_client_count", "客户端建立连接时延计算次数"},
			LATENCY_RTT_SERVER: {"rtt_server_count", "服务端建立连接时延计算次数"},
			LATENCY_SRT:        {"srt_count", "系统响应时延计算次数"},
			LATENCY_ART:        {"art_count", "应用响应时延计算次数"},
			LATENCY_RRT:        {"rrt_count", "应用请求响应时延计算次数"},
			LATENCY_CIT:        {"cit_count", "Client idle time calculation times"},
		},
		ckdb.UInt64)
	maxColumns := ckdb.NewColumnsWithComment(
		[][2]string{
			LATENCY_RTT:        {"rtt_max", "建立连接RTT最大值(us)"},
			LATENCY_RTT_CLIENT: {"rtt_client_max", "客户端建立连接RTT最大值(us)"},
			LATENCY_RTT_SERVER: {"rtt_server_max", "服务端建立连接RTT最大值(us)"},
			LATENCY_SRT:        {"srt_max", "所有系统响应时延最大值(us)"},
			LATENCY_ART:        {"art_max", "所有应用响应时延最大值(us)"},
			LATENCY_RRT:        {"rrt_max", "所有应用请求响应时延最大值(us)"},
			LATENCY_CIT:        {"cit_max", "Max client idle time(us)"},
		}, ckdb.UInt32)
	for _, c := range maxColumns {
		c.SetIndex(ckdb.IndexNone)
	}
	columns := []*ckdb.Column{}
	columns = append(columns, sumColumns...)
	columns = append(columns, counterColumns...)
	columns = append(columns, maxColumns...)
	return columns
}

// WriteBlock和LatencyColumns的列需要按顺序一一对应
func (l *Latency) WriteBlock(block *ckdb.Block) {
	block.Write(
		float64(l.RTTSum),
		float64(l.RTTClientSum),
		float64(l.RTTServerSum),
		float64(l.SRTSum),
		float64(l.ARTSum),
		float64(l.RRTSum),
		float64(l.CITSum),

		uint64(l.RTTCount),
		uint64(l.RTTClientCount),
		uint64(l.RTTServerCount),
		uint64(l.SRTCount),
		uint64(l.ARTCount),
		uint64(l.RRTCount),
		uint64(l.CITCount),

		l.RTTMax,
		l.RTTClientMax,
		l.RTTServerMax,
		l.SRTMax,
		l.ARTMax,
		l.RRTMax,
		l.CITMax,
	)

}

type Performance struct {
	RetransTx     uint64 `json:"retrans_tx" category:"$metrics"`
	RetransRx     uint64 `json:"retrans_rx" category:"$metrics"`
	ZeroWinTx     uint64 `json:"zero_win_tx" category:"$metrics"`
	ZeroWinRx     uint64 `json:"zero_win_rx" category:"$metrics"`
	RetransSyn    uint32 `json:"retrans_syn" category:"$metrics"`
	RetransSynack uint32 `json:"retrans_synack" category:"$metrics"`
}

func (a *Performance) Reverse() {
	// 性能统计量以客户端、服务端为视角，无需Reverse
}

func (a *Performance) WriteToPB(p *pb.Performance) {
	p.RetransTx = a.RetransTx
	p.RetransRx = a.RetransRx
	p.ZeroWinTx = a.ZeroWinTx
	p.ZeroWinRx = a.ZeroWinRx
	p.RetransSyn = a.RetransSyn
	p.RetransSynack = a.RetransSynack
}

func (a *Performance) ReadFromPB(p *pb.Performance) {
	a.RetransTx = p.RetransTx
	a.RetransRx = p.RetransRx
	a.ZeroWinTx = p.ZeroWinTx
	a.ZeroWinRx = p.ZeroWinRx
	a.RetransSyn = p.RetransSyn
	a.RetransSynack = p.RetransSynack
}

func (a *Performance) ConcurrentMerge(other *Performance) {
	a.RetransTx += other.RetransTx
	a.RetransRx += other.RetransRx
	a.ZeroWinTx += other.ZeroWinTx
	a.ZeroWinRx += other.ZeroWinRx
	a.RetransSyn += other.RetransSyn
	a.RetransSynack += other.RetransSynack
}

func (a *Performance) SequentialMerge(other *Performance) {
	a.ConcurrentMerge(other)
}

func (a *Performance) MarshalTo(b []byte) int {
	fields := []string{
		"retrans_tx=", "retrans_rx=", "retrans=", "zero_win_tx=", "zero_win_rx=", "zero_win=", "retrans_syn=", "retrans_synack",
	}
	values := []uint64{
		a.RetransTx, a.RetransRx, a.RetransTx + a.RetransRx, a.ZeroWinTx, a.ZeroWinRx, a.ZeroWinTx + a.ZeroWinRx, uint64(a.RetransSyn), uint64(a.RetransSynack),
	}
	return marshalKeyValues(b, fields, values)
}

const (
	PERF_RETRANS_TX = iota
	PERF_RETRANS_RX
	PERF_RETRANS

	PERF_ZERO_WIN_TX
	PERF_ZERO_WIN_RX
	PERF_ZERO_WIN

	PERF_RETRANS_SYN
	PERF_RETRANS_SYNACK
)

// Columns列和WriteBlock的列需要按顺序一一对应
func PerformanceColumns() []*ckdb.Column {
	return ckdb.NewColumnsWithComment(
		[][2]string{
			PERF_RETRANS_TX: {"retrans_tx", "客户端累计重传次数"},
			PERF_RETRANS_RX: {"retrans_rx", "服务端累计重传次数"},
			PERF_RETRANS:    {"retrans", "累计重传次数"},

			PERF_ZERO_WIN_TX: {"zero_win_tx", "客户端累计零窗次数"},
			PERF_ZERO_WIN_RX: {"zero_win_rx", "服务端累计零窗次数"},
			PERF_ZERO_WIN:    {"zero_win", "累计零窗次数"},

			PERF_RETRANS_SYN:    {"retrans_syn", "Total client retransmit SYN times"},
			PERF_RETRANS_SYNACK: {"retrans_synack", "Total server retransmit SYNACK times"},
		},
		ckdb.UInt64)
}

// WriteBlock的列和PerformanceColumns需要按顺序一一对应
func (a *Performance) WriteBlock(block *ckdb.Block) {
	block.Write(
		a.RetransTx, a.RetransRx, a.RetransTx+a.RetransRx,
		a.ZeroWinTx, a.ZeroWinRx, a.ZeroWinTx+a.ZeroWinRx,
		uint64(a.RetransSyn), uint64(a.RetransSynack),
	)
}

type Anomaly struct {
	ClientRstFlow       uint64 `json:"client_rst_flow" category:"$metrics" sub:"tcp_error"`
	ServerRstFlow       uint64 `json:"server_rst_flow" category:"$metrics" sub:"tcp_error"`
	ServerSynMiss       uint64 `json:"server_syn_miss" category:"$metrics" sub:"tcp_error"`
	ClientAckMiss       uint64 `json:"client_ack_miss" category:"$metrics" sub:"tcp_error"`
	ClientHalfCloseFlow uint64 `json:"client_half_close_flow" category:"$metrics" sub:"tcp_error"`
	ServerHalfCloseFlow uint64 `json:"server_half_close_flow" category:"$metrics" sub:"tcp_error"`

	ClientSourcePortReuse uint64 `json:"client_source_port_reuse" category:"$metrics" sub:"tcp_error"`
	ClientEstablishReset  uint64 `json:"client_establish_other_rst" category:"$metrics" sub:"tcp_error"`
	ServerReset           uint64 `json:"server_reset" category:"$metrics" sub:"tcp_error"`
	ServerQueueLack       uint64 `json:"server_queue_lack" category:"$metrics" sub:"tcp_error"`
	ServerEstablishReset  uint64 `json:"server_establish_other_rst" category:"$metrics" sub:"tcp_error"`
	TCPTimeout            uint64 `json:"tcp_timeout" category:"$metrics" sub:"tcp_error"`

	ClientEstablishFail uint64 `json:"client_establish_fail" category:"$metrics" sub:"tcp_error"`
	ServerEstablishFail uint64 `json:"server_establish_fail" category:"$metrics" sub:"tcp_error"`
	TCPEstablishFail    uint64 `json:"tcp_establish_fail" category:"$metrics" sub:"tcp_error"`
	TCPTransferFail     uint64 `json:"tcp_transfer_fail" category:"$metrics" sub:"tcp_error"`
	TCPRstFail          uint64 `json:"tcp_rst_fail" category:"$metrics" sub:"tcp_error"`

	L7ClientError uint32 `json:"l7_client_error" category:"$metrics" sub:"application"`
	L7ServerError uint32 `json:"l7_server_error" category:"$metrics" sub:"application"`
	L7Timeout     uint32 `json:"l7_timeout" category:"$metrics" sub:"application"`
}

func (_ *Anomaly) Reverse() {
	// 异常统计量以客户端、服务端为视角，无需Reverse
}

func (a *Anomaly) WriteToPB(p *pb.Anomaly) {
	p.ClientRstFlow = a.ClientRstFlow
	p.ServerRstFlow = a.ServerRstFlow
	p.ServerSynMiss = a.ServerSynMiss
	p.ClientAckMiss = a.ClientAckMiss
	p.ClientHalfCloseFlow = a.ClientHalfCloseFlow
	p.ServerHalfCloseFlow = a.ServerHalfCloseFlow

	p.ClientSourcePortReuse = a.ClientSourcePortReuse
	p.ClientEstablishReset = a.ClientEstablishReset
	p.ServerReset = a.ServerReset
	p.ServerQueueLack = a.ServerQueueLack
	p.ServerEstablishReset = a.ServerEstablishReset
	p.TcpTimeout = a.TCPTimeout

	p.L7ClientError = a.L7ClientError
	p.L7ServerError = a.L7ServerError
	p.L7Timeout = a.L7Timeout
}

func (a *Anomaly) ReadFromPB(p *pb.Anomaly) {
	a.ClientRstFlow = p.ClientRstFlow
	a.ServerRstFlow = p.ServerRstFlow
	a.ServerSynMiss = p.ServerSynMiss
	a.ClientAckMiss = p.ClientAckMiss
	a.ClientHalfCloseFlow = p.ClientHalfCloseFlow
	a.ServerHalfCloseFlow = p.ServerHalfCloseFlow

	a.ClientSourcePortReuse = p.ClientSourcePortReuse
	a.ClientEstablishReset = p.ClientEstablishReset
	a.ServerReset = p.ServerReset
	a.ServerQueueLack = p.ServerQueueLack
	a.ServerEstablishReset = p.ServerEstablishReset
	a.TCPTimeout = p.TcpTimeout

	a.ClientEstablishFail = a.ClientAckMiss + a.ClientSourcePortReuse + a.ClientEstablishReset
	a.ServerEstablishFail = a.ServerSynMiss + a.ServerReset + a.ServerQueueLack + a.ServerEstablishReset
	a.TCPEstablishFail = a.ClientEstablishFail + a.ServerEstablishFail
	// 表示 传输-客户端/服务端重置, 传输-服务端队列溢出, 传输-连接超时次数
	a.TCPTransferFail = a.ClientRstFlow + a.ServerRstFlow + a.ServerQueueLack + a.TCPTimeout
	// 表示所有重置的次数之和，包含建连-客户端/服务端其他重置、建连-服务端直接重置、传输-客户端/服务端重置
	a.TCPRstFail = a.ClientEstablishReset + a.ServerEstablishReset + a.ServerReset + a.ClientRstFlow + a.ServerRstFlow

	a.L7ClientError = p.L7ClientError
	a.L7ServerError = p.L7ServerError
	a.L7Timeout = p.L7Timeout
}

func (a *Anomaly) ConcurrentMerge(other *Anomaly) {
	a.ClientRstFlow += other.ClientRstFlow
	a.ServerRstFlow += other.ServerRstFlow
	a.ServerSynMiss += other.ServerSynMiss
	a.ClientAckMiss += other.ClientAckMiss
	a.ClientHalfCloseFlow += other.ClientHalfCloseFlow
	a.ServerHalfCloseFlow += other.ServerHalfCloseFlow

	a.ClientSourcePortReuse += other.ClientSourcePortReuse
	a.ClientEstablishReset += other.ClientEstablishReset
	a.ServerReset += other.ServerReset
	a.ServerQueueLack += other.ServerQueueLack
	a.ServerEstablishReset += other.ServerEstablishReset
	a.TCPTimeout += other.TCPTimeout

	a.L7ClientError += other.L7ClientError
	a.L7ServerError += other.L7ServerError
	a.L7Timeout += other.L7Timeout
}

func (a *Anomaly) SequentialMerge(other *Anomaly) {
	a.ConcurrentMerge(other)
}

func (a *Anomaly) MarshalTo(b []byte) int {
	fields := []string{
		"client_rst_flow=", "server_rst_flow=",
		"server_syn_miss=", "client_ack_miss=",
		"client_half_close_flow=", "server_half_close_flow=",
		"client_source_port_reuse=", "server_reset=", "server_queue_lack=",
		"client_establish_other_rst=", "server_establish_other_rst=",
		"tcp_timeout=",
		"client_establish_fail=", "server_establish_fail=", "tcp_establish_fail=",
		"l7_client_error=", "l7_server_error=", "l7_timeout=", "l7_error=",
	}
	clientFail := a.ClientAckMiss + a.ClientSourcePortReuse + a.ClientEstablishReset
	serverFail := a.ServerSynMiss + a.ServerReset + a.ServerQueueLack + a.ServerEstablishReset
	values := []uint64{
		a.ClientRstFlow, a.ServerRstFlow,
		a.ServerSynMiss, a.ClientAckMiss,
		a.ClientHalfCloseFlow, a.ServerHalfCloseFlow,
		a.ClientSourcePortReuse, a.ServerReset, a.ServerQueueLack,
		a.ClientEstablishReset, a.ServerEstablishReset,
		a.TCPTimeout,
		clientFail, serverFail, clientFail + serverFail,
		uint64(a.L7ClientError), uint64(a.L7ServerError), uint64(a.L7Timeout), uint64(a.L7ClientError + a.L7ServerError),
	}
	return marshalKeyValues(b, fields, values)
}

const (
	ANOMALY_CLIENT_RST_FLOW = iota
	ANOMALY_SERVER_RST_FLOW

	ANOMALY_SERVER_SYN_MISS
	ANOMALY_CLIENT_ACK_MISS

	ANOMALY_CLIENT_HALF_CLOSE_FLOW
	ANOMALY_SERVER_HALF_CLOSE_FLOW

	ANOMALY_CLIENT_SOURCE_PORT_REUSE
	ANOMALY_SERVER_RESET
	ANOMALY_SERVER_QUEUE_LACK

	ANOMALY_CLIENT_ESTABLISH_OTHER_RST
	ANOMALY_SERVER_ESTABLISH_OTHER_RST

	ANOMALY_TCP_TIMEOUT

	ANOMALY_CLIENT_ESTABLISH_FAIL
	ANOMALY_SERVER_ESTABLISH_FAIL
	ANOMALY_TCP_ESTABLISH_FAIL

	ANOMALY_TRANSFER_FAIL
	ANOMALY_RST_FAIL
)
const (
	ANOMALY_L7_CLIENT_ERROR = iota
	ANOMALY_L7_SERVER_ERROR
	ANOMALY_L7_TIMEOUT
	ANOMALY_L7_ERROR
)

// Columns列和WriteBlock的列需要按顺序一一对应
func AnomalyColumns() []*ckdb.Column {
	anomalColumns := ckdb.NewColumnsWithComment(
		[][2]string{
			ANOMALY_CLIENT_RST_FLOW: {"client_rst_flow", "传输-客户端重置"},
			ANOMALY_SERVER_RST_FLOW: {"server_rst_flow", "传输-服务端重置"},

			ANOMALY_SERVER_SYN_MISS: {"server_syn_miss", "建连-服务端 SYN 缺失"},
			ANOMALY_CLIENT_ACK_MISS: {"client_ack_miss", "建连-客户端 ACK 缺失"},

			ANOMALY_CLIENT_HALF_CLOSE_FLOW: {"client_half_close_flow", "传输-客户端半关"},
			ANOMALY_SERVER_HALF_CLOSE_FLOW: {"server_half_close_flow", "传输-服务端半关"},

			ANOMALY_CLIENT_SOURCE_PORT_REUSE: {"client_source_port_reuse", "建连-客户端端口复用"},
			ANOMALY_SERVER_RESET:             {"server_reset", "建连-服务端直接重置"},
			ANOMALY_SERVER_QUEUE_LACK:        {"server_queue_lack", "传输-服务端队列溢出"},

			ANOMALY_CLIENT_ESTABLISH_OTHER_RST: {"client_establish_other_rst", "建连-客户端其他重置"},
			ANOMALY_SERVER_ESTABLISH_OTHER_RST: {"server_establish_other_rst", "建连-服务端其他重置"},

			ANOMALY_TCP_TIMEOUT: {"tcp_timeout", "传输-连接超时次数"},

			ANOMALY_CLIENT_ESTABLISH_FAIL: {"client_establish_fail", "TCP客户端建连失败次数"},
			ANOMALY_SERVER_ESTABLISH_FAIL: {"server_establish_fail", "TCP服务端建连失败次数"},
			ANOMALY_TCP_ESTABLISH_FAIL:    {"tcp_establish_fail", "TCP建连失败次数"},

			ANOMALY_TRANSFER_FAIL: {"tcp_transfer_fail", "TCP传输失败次数"},
			ANOMALY_RST_FAIL:      {"tcp_rst_fail", "TCP重置次数"},
		}, ckdb.UInt64)

	l7AnomalColumns := ckdb.NewColumnsWithComment(
		[][2]string{
			ANOMALY_L7_CLIENT_ERROR: {"l7_client_error", "应用客户端异常次数"},
			ANOMALY_L7_SERVER_ERROR: {"l7_server_error", "应用服务端异常次数"},
			ANOMALY_L7_TIMEOUT:      {"l7_timeout", "应用请求超时次数"},
			ANOMALY_L7_ERROR:        {"l7_error", "应用异常次数"},
		}, ckdb.UInt32)

	return append(anomalColumns, l7AnomalColumns...)
}

// WriteBlock的列和AnomalyColumns需要按顺序一一对应
func (a *Anomaly) WriteBlock(block *ckdb.Block) {
	block.Write(
		a.ClientRstFlow,
		a.ServerRstFlow,

		a.ServerSynMiss,
		a.ClientAckMiss,

		a.ClientHalfCloseFlow,
		a.ServerHalfCloseFlow,

		a.ClientSourcePortReuse,
		a.ServerReset,
		a.ServerQueueLack,

		a.ClientEstablishReset,
		a.ServerEstablishReset,

		a.TCPTimeout,

		a.ClientEstablishFail,
		a.ServerEstablishFail,
		a.TCPEstablishFail,
		a.TCPTransferFail,
		a.TCPRstFail,

		a.L7ClientError,
		a.L7ServerError,
		a.L7Timeout,
		a.L7ClientError+a.L7ServerError,
	)
}

type FlowLoad struct {
	Load uint64 `json:"flow_load" category:"$metrics" sub:"l4_throughput"`
}

func (l *FlowLoad) Reverse() {
	// 负载统计量无方向，无需Reverse
}

func (l *FlowLoad) WriteToPB(p *pb.FlowLoad) {
	p.Load = l.Load
}

func (l *FlowLoad) ReadFromPB(p *pb.FlowLoad) {
	l.Load = p.Load
}

func (l *FlowLoad) ConcurrentMerge(other *FlowLoad) {
	l.Load += other.Load
}

func (l *FlowLoad) SequentialMerge(other *FlowLoad) {
	l.ConcurrentMerge(other)
}

func (l *FlowLoad) MarshalTo(b []byte) int {
	fields := []string{"flow_load="}
	values := []uint64{l.Load}
	return marshalKeyValues(b, fields, values)
}

const (
	FLOW_LOAD = iota
)

func FlowLoadColumns() []*ckdb.Column {
	return ckdb.NewColumnsWithComment([][2]string{FLOW_LOAD: {"flow_load", "累计活跃连接数"}}, ckdb.UInt64)
}

func (l *FlowLoad) WriteBlock(block *ckdb.Block) {
	block.Write(l.Load)
}

func marshalKeyValues(b []byte, fields []string, values []uint64) int {
	if len(fields) != len(values) {
		panic("fields和values长度不相等")
	}
	offset := 0
	for i := range fields {
		v := values[i]
		if v == 0 {
			continue
		}
		if offset > 0 {
			b[offset] = ','
			offset++
		}
		offset += copy(b[offset:], fields[i])
		offset += copy(b[offset:], strconv.FormatUint(v, 10))
		b[offset] = 'i'
		offset++
	}

	return offset
}
