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

type AppTrafficBlock struct {
	ColRequest        proto.ColUInt32
	ColResponse       proto.ColUInt32
	ColDirectionScore proto.ColUInt8
}

func (b *AppTrafficBlock) Reset() {
	b.ColRequest.Reset()
	b.ColResponse.Reset()
	b.ColDirectionScore.Reset()
}

func (b *AppTrafficBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_REQUEST, Data: &b.ColRequest},
		proto.InputColumn{Name: ckdb.COLUMN_RESPONSE, Data: &b.ColResponse},
		proto.InputColumn{Name: ckdb.COLUMN_DIRECTION_SCORE, Data: &b.ColDirectionScore},
	)
}

func (n *AppTraffic) NewColumnBlock() ckdb.CKColumnBlock {
	return &AppTrafficBlock{}
}

func (n *AppTraffic) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*AppTrafficBlock)
	block.ColRequest.Append(n.Request)
	block.ColResponse.Append(n.Response)
	block.ColDirectionScore.Append(n.DirectionScore)
}

type AppLatencyBlock struct {
	ColRrtMax   proto.ColUInt32
	ColRrtSum   proto.ColFloat64
	ColRrtCount proto.ColUInt64
}

func (b *AppLatencyBlock) Reset() {
	b.ColRrtMax.Reset()
	b.ColRrtSum.Reset()
	b.ColRrtCount.Reset()
}

func (b *AppLatencyBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_RRT_MAX, Data: &b.ColRrtMax},
		proto.InputColumn{Name: ckdb.COLUMN_RRT_SUM, Data: &b.ColRrtSum},
		proto.InputColumn{Name: ckdb.COLUMN_RRT_COUNT, Data: &b.ColRrtCount},
	)
}

func (n *AppLatency) NewColumnBlock() ckdb.CKColumnBlock {
	return &AppLatencyBlock{}
}

func (n *AppLatency) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*AppLatencyBlock)
	block.ColRrtMax.Append(n.RRTMax)
	block.ColRrtSum.Append(float64(n.RRTSum))
	block.ColRrtCount.Append(uint64(n.RRTCount))
}

type AppAnomalyBlock struct {
	ColClientError proto.ColUInt64
	ColServerError proto.ColUInt64
	ColTimeout     proto.ColUInt64
	ColError       proto.ColUInt64
}

func (b *AppAnomalyBlock) Reset() {
	b.ColClientError.Reset()
	b.ColServerError.Reset()
	b.ColTimeout.Reset()
	b.ColError.Reset()
}

func (b *AppAnomalyBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_CLIENT_ERROR, Data: &b.ColClientError},
		proto.InputColumn{Name: ckdb.COLUMN_SERVER_ERROR, Data: &b.ColServerError},
		proto.InputColumn{Name: ckdb.COLUMN_TIMEOUT, Data: &b.ColTimeout},
		proto.InputColumn{Name: ckdb.COLUMN_ERROR, Data: &b.ColError},
	)
}

func (n *AppAnomaly) NewColumnBlock() ckdb.CKColumnBlock {
	return &AppAnomalyBlock{}
}

func (n *AppAnomaly) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*AppAnomalyBlock)
	block.ColClientError.Append(uint64(n.ClientError))
	block.ColServerError.Append(uint64(n.ServerError))
	block.ColTimeout.Append(uint64(n.Timeout))
	block.ColError.Append(uint64(n.ClientError + n.ServerError))
}

type AppMeterBlock struct {
	AppTrafficBlock
	AppLatencyBlock
	AppAnomalyBlock
}

func (b *AppMeterBlock) Reset() {
	b.AppTrafficBlock.Reset()
	b.AppLatencyBlock.Reset()
	b.AppAnomalyBlock.Reset()
}

func (b *AppMeterBlock) ToInput(input proto.Input) proto.Input {
	input = b.AppTrafficBlock.ToInput(input)
	input = b.AppLatencyBlock.ToInput(input)
	input = b.AppAnomalyBlock.ToInput(input)
	return input
}

func (n *AppMeter) NewColumnBlock() ckdb.CKColumnBlock {
	return &AppMeterBlock{}
}

func (n *AppMeter) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*AppMeterBlock)
	n.AppTraffic.AppendToColumnBlock(&block.AppTrafficBlock)
	n.AppLatency.AppendToColumnBlock(&block.AppLatencyBlock)
	n.AppAnomaly.AppendToColumnBlock(&block.AppAnomalyBlock)
}
