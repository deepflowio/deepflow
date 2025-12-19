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
	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type TrafficBlock struct {
	ColPacketTx       proto.ColUInt64
	ColPacketRx       proto.ColUInt64
	ColPacket         proto.ColUInt64
	ColByteTx         proto.ColUInt64
	ColByteRx         proto.ColUInt64
	ColByte           proto.ColUInt64
	ColL3ByteTx       proto.ColUInt64
	ColL3ByteRx       proto.ColUInt64
	ColL4ByteTx       proto.ColUInt64
	ColL4ByteRx       proto.ColUInt64
	ColNewFlow        proto.ColUInt64
	ColClosedFlow     proto.ColUInt64
	ColL7Request      proto.ColUInt64
	ColL7Response     proto.ColUInt64
	ColSynCount       proto.ColUInt64
	ColSynackCount    proto.ColUInt64
	ColDirectionScore proto.ColUInt8
}

func (b *TrafficBlock) Reset() {
	b.ColPacketTx.Reset()
	b.ColPacketRx.Reset()
	b.ColPacket.Reset()
	b.ColByteTx.Reset()
	b.ColByteRx.Reset()
	b.ColByte.Reset()
	b.ColL3ByteTx.Reset()
	b.ColL3ByteRx.Reset()
	b.ColL4ByteTx.Reset()
	b.ColL4ByteRx.Reset()
	b.ColNewFlow.Reset()
	b.ColClosedFlow.Reset()
	b.ColL7Request.Reset()
	b.ColL7Response.Reset()
	b.ColSynCount.Reset()
	b.ColSynackCount.Reset()
	b.ColDirectionScore.Reset()
}

func (b *TrafficBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_PACKET_TX, Data: &b.ColPacketTx},
		proto.InputColumn{Name: ckdb.COLUMN_PACKET_RX, Data: &b.ColPacketRx},
		proto.InputColumn{Name: ckdb.COLUMN_PACKET, Data: &b.ColPacket},
		proto.InputColumn{Name: ckdb.COLUMN_BYTE_TX, Data: &b.ColByteTx},
		proto.InputColumn{Name: ckdb.COLUMN_BYTE_RX, Data: &b.ColByteRx},
		proto.InputColumn{Name: ckdb.COLUMN_BYTE, Data: &b.ColByte},
		proto.InputColumn{Name: ckdb.COLUMN_L3_BYTE_TX, Data: &b.ColL3ByteTx},
		proto.InputColumn{Name: ckdb.COLUMN_L3_BYTE_RX, Data: &b.ColL3ByteRx},
		proto.InputColumn{Name: ckdb.COLUMN_L4_BYTE_TX, Data: &b.ColL4ByteTx},
		proto.InputColumn{Name: ckdb.COLUMN_L4_BYTE_RX, Data: &b.ColL4ByteRx},
		proto.InputColumn{Name: ckdb.COLUMN_NEW_FLOW, Data: &b.ColNewFlow},
		proto.InputColumn{Name: ckdb.COLUMN_CLOSED_FLOW, Data: &b.ColClosedFlow},
		proto.InputColumn{Name: ckdb.COLUMN_L7_REQUEST, Data: &b.ColL7Request},
		proto.InputColumn{Name: ckdb.COLUMN_L7_RESPONSE, Data: &b.ColL7Response},
		proto.InputColumn{Name: ckdb.COLUMN_SYN_COUNT, Data: &b.ColSynCount},
		proto.InputColumn{Name: ckdb.COLUMN_SYNACK_COUNT, Data: &b.ColSynackCount},
		proto.InputColumn{Name: ckdb.COLUMN_DIRECTION_SCORE, Data: &b.ColDirectionScore},
	)
}

func (n *Traffic) NewColumnBlock() ckdb.CKColumnBlock {
	return &TrafficBlock{}
}

func (n *Traffic) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*TrafficBlock)
	block.ColPacketTx.Append(n.PacketTx)
	block.ColPacketRx.Append(n.PacketRx)
	block.ColPacket.Append(n.PacketTx + n.PacketRx)
	block.ColByteTx.Append(n.ByteTx)
	block.ColByteRx.Append(n.ByteRx)
	block.ColByte.Append(n.ByteTx + n.ByteRx)
	block.ColL3ByteTx.Append(n.L3ByteTx)
	block.ColL3ByteRx.Append(n.L3ByteRx)
	block.ColL4ByteTx.Append(n.L4ByteTx)
	block.ColL4ByteRx.Append(n.L4ByteRx)
	block.ColNewFlow.Append(n.NewFlow)
	block.ColClosedFlow.Append(n.ClosedFlow)
	block.ColL7Request.Append(uint64(n.L7Request))
	block.ColL7Response.Append(uint64(n.L7Response))
	block.ColSynCount.Append(uint64(n.SynCount))
	block.ColSynackCount.Append(uint64(n.SynackCount))
	block.ColDirectionScore.Append(n.DirectionScore)
}

type LatencyBlock struct {
	ColRttSum         proto.ColFloat64
	ColRttClientSum   proto.ColFloat64
	ColRttServerSum   proto.ColFloat64
	ColSrtSum         proto.ColFloat64
	ColArtSum         proto.ColFloat64
	ColRrtSum         proto.ColFloat64
	ColCitSum         proto.ColFloat64
	ColRttCount       proto.ColUInt64
	ColRttClientCount proto.ColUInt64
	ColRttServerCount proto.ColUInt64
	ColSrtCount       proto.ColUInt64
	ColArtCount       proto.ColUInt64
	ColRrtCount       proto.ColUInt64
	ColCitCount       proto.ColUInt64
	ColRttMax         proto.ColUInt32
	ColRttClientMax   proto.ColUInt32
	ColRttServerMax   proto.ColUInt32
	ColSrtMax         proto.ColUInt32
	ColArtMax         proto.ColUInt32
	ColRrtMax         proto.ColUInt32
	ColCitMax         proto.ColUInt32
}

func (b *LatencyBlock) Reset() {
	b.ColRttSum.Reset()
	b.ColRttClientSum.Reset()
	b.ColRttServerSum.Reset()
	b.ColSrtSum.Reset()
	b.ColArtSum.Reset()
	b.ColRrtSum.Reset()
	b.ColCitSum.Reset()
	b.ColRttCount.Reset()
	b.ColRttClientCount.Reset()
	b.ColRttServerCount.Reset()
	b.ColSrtCount.Reset()
	b.ColArtCount.Reset()
	b.ColRrtCount.Reset()
	b.ColCitCount.Reset()
	b.ColRttMax.Reset()
	b.ColRttClientMax.Reset()
	b.ColRttServerMax.Reset()
	b.ColSrtMax.Reset()
	b.ColArtMax.Reset()
	b.ColRrtMax.Reset()
	b.ColCitMax.Reset()
}

func (b *LatencyBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_RTT_SUM, Data: &b.ColRttSum},
		proto.InputColumn{Name: ckdb.COLUMN_RTT_CLIENT_SUM, Data: &b.ColRttClientSum},
		proto.InputColumn{Name: ckdb.COLUMN_RTT_SERVER_SUM, Data: &b.ColRttServerSum},
		proto.InputColumn{Name: ckdb.COLUMN_SRT_SUM, Data: &b.ColSrtSum},
		proto.InputColumn{Name: ckdb.COLUMN_ART_SUM, Data: &b.ColArtSum},
		proto.InputColumn{Name: ckdb.COLUMN_RRT_SUM, Data: &b.ColRrtSum},
		proto.InputColumn{Name: ckdb.COLUMN_CIT_SUM, Data: &b.ColCitSum},
		proto.InputColumn{Name: ckdb.COLUMN_RTT_COUNT, Data: &b.ColRttCount},
		proto.InputColumn{Name: ckdb.COLUMN_RTT_CLIENT_COUNT, Data: &b.ColRttClientCount},
		proto.InputColumn{Name: ckdb.COLUMN_RTT_SERVER_COUNT, Data: &b.ColRttServerCount},
		proto.InputColumn{Name: ckdb.COLUMN_SRT_COUNT, Data: &b.ColSrtCount},
		proto.InputColumn{Name: ckdb.COLUMN_ART_COUNT, Data: &b.ColArtCount},
		proto.InputColumn{Name: ckdb.COLUMN_RRT_COUNT, Data: &b.ColRrtCount},
		proto.InputColumn{Name: ckdb.COLUMN_CIT_COUNT, Data: &b.ColCitCount},
		proto.InputColumn{Name: ckdb.COLUMN_RTT_MAX, Data: &b.ColRttMax},
		proto.InputColumn{Name: ckdb.COLUMN_RTT_CLIENT_MAX, Data: &b.ColRttClientMax},
		proto.InputColumn{Name: ckdb.COLUMN_RTT_SERVER_MAX, Data: &b.ColRttServerMax},
		proto.InputColumn{Name: ckdb.COLUMN_SRT_MAX, Data: &b.ColSrtMax},
		proto.InputColumn{Name: ckdb.COLUMN_ART_MAX, Data: &b.ColArtMax},
		proto.InputColumn{Name: ckdb.COLUMN_RRT_MAX, Data: &b.ColRrtMax},
		proto.InputColumn{Name: ckdb.COLUMN_CIT_MAX, Data: &b.ColCitMax},
	)
}

func (n *Latency) NewColumnBlock() ckdb.CKColumnBlock {
	return &LatencyBlock{}
}

func (n *Latency) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*LatencyBlock)
	block.ColRttSum.Append(float64(n.RTTSum))
	block.ColRttClientSum.Append(float64(n.RTTClientSum))
	block.ColRttServerSum.Append(float64(n.RTTServerSum))
	block.ColSrtSum.Append(float64(n.SRTSum))
	block.ColArtSum.Append(float64(n.ARTSum))
	block.ColRrtSum.Append(float64(n.RRTSum))
	block.ColCitSum.Append(float64(n.CITSum))
	block.ColRttCount.Append(uint64(n.RTTCount))
	block.ColRttClientCount.Append(uint64(n.RTTClientCount))
	block.ColRttServerCount.Append(uint64(n.RTTServerCount))
	block.ColSrtCount.Append(uint64(n.SRTCount))
	block.ColArtCount.Append(uint64(n.ARTCount))
	block.ColRrtCount.Append(uint64(n.RRTCount))
	block.ColCitCount.Append(uint64(n.CITCount))
	block.ColRttMax.Append(n.RTTMax)
	block.ColRttClientMax.Append(n.RTTClientMax)
	block.ColRttServerMax.Append(n.RTTServerMax)
	block.ColSrtMax.Append(n.SRTMax)
	block.ColArtMax.Append(n.ARTMax)
	block.ColRrtMax.Append(n.RRTMax)
	block.ColCitMax.Append(n.CITMax)
}

type PerformanceBlock struct {
	ColRetransTx     proto.ColUInt64
	ColRetransRx     proto.ColUInt64
	ColRetrans       proto.ColUInt64
	ColZeroWinTx     proto.ColUInt64
	ColZeroWinRx     proto.ColUInt64
	ColZeroWin       proto.ColUInt64
	ColRetransSyn    proto.ColUInt64
	ColRetransSynack proto.ColUInt64
	ColOooTx         proto.ColUInt64
	ColOooRx         proto.ColUInt64
}

func (b *PerformanceBlock) Reset() {
	b.ColRetransTx.Reset()
	b.ColRetransRx.Reset()
	b.ColRetrans.Reset()
	b.ColZeroWinTx.Reset()
	b.ColZeroWinRx.Reset()
	b.ColZeroWin.Reset()
	b.ColRetransSyn.Reset()
	b.ColRetransSynack.Reset()
	b.ColOooTx.Reset()
	b.ColOooRx.Reset()
}

func (b *PerformanceBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_RETRANS_TX, Data: &b.ColRetransTx},
		proto.InputColumn{Name: ckdb.COLUMN_RETRANS_RX, Data: &b.ColRetransRx},
		proto.InputColumn{Name: ckdb.COLUMN_RETRANS, Data: &b.ColRetrans},
		proto.InputColumn{Name: ckdb.COLUMN_ZERO_WIN_TX, Data: &b.ColZeroWinTx},
		proto.InputColumn{Name: ckdb.COLUMN_ZERO_WIN_RX, Data: &b.ColZeroWinRx},
		proto.InputColumn{Name: ckdb.COLUMN_ZERO_WIN, Data: &b.ColZeroWin},
		proto.InputColumn{Name: ckdb.COLUMN_RETRANS_SYN, Data: &b.ColRetransSyn},
		proto.InputColumn{Name: ckdb.COLUMN_RETRANS_SYNACK, Data: &b.ColRetransSynack},
		proto.InputColumn{Name: ckdb.COLUMN_OOO_TX, Data: &b.ColOooTx},
		proto.InputColumn{Name: ckdb.COLUMN_OOO_RX, Data: &b.ColOooRx},
	)
}

func (n *Performance) NewColumnBlock() ckdb.CKColumnBlock {
	return &PerformanceBlock{}
}

func (n *Performance) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*PerformanceBlock)
	block.ColRetransTx.Append(n.RetransTx)
	block.ColRetransRx.Append(n.RetransRx)
	block.ColRetrans.Append(n.RetransTx + n.RetransRx)
	block.ColZeroWinTx.Append(n.ZeroWinTx)
	block.ColZeroWinRx.Append(n.ZeroWinRx)
	block.ColZeroWin.Append(n.ZeroWinTx + n.ZeroWinRx)
	block.ColRetransSyn.Append(uint64(n.RetransSyn))
	block.ColRetransSynack.Append(uint64(n.RetransSynack))
	block.ColOooTx.Append(n.OooTx)
	block.ColOooRx.Append(n.OooRx)
}

type AnomalyBlock struct {
	ColClientRstFlow           proto.ColUInt64
	ColServerRstFlow           proto.ColUInt64
	ColServerSynMiss           proto.ColUInt64
	ColClientAckMiss           proto.ColUInt64
	ColClientHalfCloseFlow     proto.ColUInt64
	ColServerHalfCloseFlow     proto.ColUInt64
	ColClientSourcePortReuse   proto.ColUInt64
	ColServerReset             proto.ColUInt64
	ColServerQueueLack         proto.ColUInt64
	ColClientEstablishOtherRst proto.ColUInt64
	ColServerEstablishOtherRst proto.ColUInt64
	ColTcpTimeout              proto.ColUInt64
	ColClientEstablishFail     proto.ColUInt64
	ColServerEstablishFail     proto.ColUInt64
	ColTcpEstablishFail        proto.ColUInt64
	ColTcpTransferFail         proto.ColUInt64
	ColTcpRstFail              proto.ColUInt64
	ColL7ClientError           proto.ColUInt32
	ColL7ServerError           proto.ColUInt32
	ColL7Timeout               proto.ColUInt32
	ColL7Error                 proto.ColUInt32
}

func (b *AnomalyBlock) Reset() {
	b.ColClientRstFlow.Reset()
	b.ColServerRstFlow.Reset()
	b.ColServerSynMiss.Reset()
	b.ColClientAckMiss.Reset()
	b.ColClientHalfCloseFlow.Reset()
	b.ColServerHalfCloseFlow.Reset()
	b.ColClientSourcePortReuse.Reset()
	b.ColServerReset.Reset()
	b.ColServerQueueLack.Reset()
	b.ColClientEstablishOtherRst.Reset()
	b.ColServerEstablishOtherRst.Reset()
	b.ColTcpTimeout.Reset()
	b.ColClientEstablishFail.Reset()
	b.ColServerEstablishFail.Reset()
	b.ColTcpEstablishFail.Reset()
	b.ColTcpTransferFail.Reset()
	b.ColTcpRstFail.Reset()
	b.ColL7ClientError.Reset()
	b.ColL7ServerError.Reset()
	b.ColL7Timeout.Reset()
	b.ColL7Error.Reset()
}

func (b *AnomalyBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_CLIENT_RST_FLOW, Data: &b.ColClientRstFlow},
		proto.InputColumn{Name: ckdb.COLUMN_SERVER_RST_FLOW, Data: &b.ColServerRstFlow},
		proto.InputColumn{Name: ckdb.COLUMN_SERVER_SYN_MISS, Data: &b.ColServerSynMiss},
		proto.InputColumn{Name: ckdb.COLUMN_CLIENT_ACK_MISS, Data: &b.ColClientAckMiss},
		proto.InputColumn{Name: ckdb.COLUMN_CLIENT_HALF_CLOSE_FLOW, Data: &b.ColClientHalfCloseFlow},
		proto.InputColumn{Name: ckdb.COLUMN_SERVER_HALF_CLOSE_FLOW, Data: &b.ColServerHalfCloseFlow},
		proto.InputColumn{Name: ckdb.COLUMN_CLIENT_SOURCE_PORT_REUSE, Data: &b.ColClientSourcePortReuse},
		proto.InputColumn{Name: ckdb.COLUMN_SERVER_RESET, Data: &b.ColServerReset},
		proto.InputColumn{Name: ckdb.COLUMN_SERVER_QUEUE_LACK, Data: &b.ColServerQueueLack},
		proto.InputColumn{Name: ckdb.COLUMN_CLIENT_ESTABLISH_OTHER_RST, Data: &b.ColClientEstablishOtherRst},
		proto.InputColumn{Name: ckdb.COLUMN_SERVER_ESTABLISH_OTHER_RST, Data: &b.ColServerEstablishOtherRst},
		proto.InputColumn{Name: ckdb.COLUMN_TCP_TIMEOUT, Data: &b.ColTcpTimeout},
		proto.InputColumn{Name: ckdb.COLUMN_CLIENT_ESTABLISH_FAIL, Data: &b.ColClientEstablishFail},
		proto.InputColumn{Name: ckdb.COLUMN_SERVER_ESTABLISH_FAIL, Data: &b.ColServerEstablishFail},
		proto.InputColumn{Name: ckdb.COLUMN_TCP_ESTABLISH_FAIL, Data: &b.ColTcpEstablishFail},
		proto.InputColumn{Name: ckdb.COLUMN_TCP_TRANSFER_FAIL, Data: &b.ColTcpTransferFail},
		proto.InputColumn{Name: ckdb.COLUMN_TCP_RST_FAIL, Data: &b.ColTcpRstFail},
		proto.InputColumn{Name: ckdb.COLUMN_L7_CLIENT_ERROR, Data: &b.ColL7ClientError},
		proto.InputColumn{Name: ckdb.COLUMN_L7_SERVER_ERROR, Data: &b.ColL7ServerError},
		proto.InputColumn{Name: ckdb.COLUMN_L7_TIMEOUT, Data: &b.ColL7Timeout},
		proto.InputColumn{Name: ckdb.COLUMN_L7_ERROR, Data: &b.ColL7Error},
	)
}

func (n *Anomaly) NewColumnBlock() ckdb.CKColumnBlock {
	return &AnomalyBlock{}
}

func (n *Anomaly) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*AnomalyBlock)
	block.ColClientRstFlow.Append(n.ClientRstFlow)
	block.ColServerRstFlow.Append(n.ServerRstFlow)
	block.ColServerSynMiss.Append(n.ServerSynMiss)
	block.ColClientAckMiss.Append(n.ClientAckMiss)
	block.ColClientHalfCloseFlow.Append(n.ClientHalfCloseFlow)
	block.ColServerHalfCloseFlow.Append(n.ServerHalfCloseFlow)
	block.ColClientSourcePortReuse.Append(n.ClientSourcePortReuse)
	block.ColServerReset.Append(n.ServerReset)
	block.ColServerQueueLack.Append(n.ServerQueueLack)
	block.ColClientEstablishOtherRst.Append(n.ClientEstablishReset)
	block.ColServerEstablishOtherRst.Append(n.ServerEstablishReset)
	block.ColTcpTimeout.Append(n.TCPTimeout)
	block.ColClientEstablishFail.Append(n.ClientEstablishFail)
	block.ColServerEstablishFail.Append(n.ServerEstablishFail)
	block.ColTcpEstablishFail.Append(n.TCPEstablishFail)
	block.ColTcpTransferFail.Append(n.TCPTransferFail)
	block.ColTcpRstFail.Append(n.TCPRstFail)
	block.ColL7ClientError.Append(n.L7ClientError)
	block.ColL7ServerError.Append(n.L7ServerError)
	block.ColL7Timeout.Append(n.L7Timeout)
	block.ColL7Error.Append(n.L7ClientError + n.L7ServerError)
}

type FlowLoadBlock struct {
	ColFlowLoad proto.ColUInt64
}

func (b *FlowLoadBlock) Reset() {
	b.ColFlowLoad.Reset()
}

func (b *FlowLoadBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_FLOW_LOAD, Data: &b.ColFlowLoad},
	)
}

func (n *FlowLoad) NewColumnBlock() ckdb.CKColumnBlock {
	return &FlowLoadBlock{}
}

func (n *FlowLoad) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*FlowLoadBlock)
	block.ColFlowLoad.Append(n.Load)
}

type FlowMeterBlock struct {
	TrafficBlock
	LatencyBlock
	PerformanceBlock
	AnomalyBlock
	FlowLoadBlock
}

func (b *FlowMeterBlock) Reset() {
	b.TrafficBlock.Reset()
	b.LatencyBlock.Reset()
	b.PerformanceBlock.Reset()
	b.AnomalyBlock.Reset()
	b.FlowLoadBlock.Reset()
}

func (b *FlowMeterBlock) ToInput(input proto.Input) proto.Input {
	input = b.TrafficBlock.ToInput(input)
	input = b.LatencyBlock.ToInput(input)
	input = b.PerformanceBlock.ToInput(input)
	input = b.AnomalyBlock.ToInput(input)
	input = b.FlowLoadBlock.ToInput(input)
	return input
}

func (n *FlowMeter) NewColumnBlock() ckdb.CKColumnBlock {
	return &FlowMeterBlock{}
}

func (n *FlowMeter) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*FlowMeterBlock)
	n.Traffic.AppendToColumnBlock(&block.TrafficBlock)
	n.Latency.AppendToColumnBlock(&block.LatencyBlock)
	n.Performance.AppendToColumnBlock(&block.PerformanceBlock)
	n.Anomaly.AppendToColumnBlock(&block.AnomalyBlock)
	n.FlowLoad.AppendToColumnBlock(&block.FlowLoadBlock)
}
