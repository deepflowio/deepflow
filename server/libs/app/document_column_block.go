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
package app

import (
	"github.com/ClickHouse/ch-go/proto"

	"github.com/deepflowio/deepflow/server/libs/ckdb"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
)

type DocumentFlowBlock struct {
	*flow_metrics.TagBlock
	*flow_metrics.FlowMeterBlock
}

func (b *DocumentFlowBlock) Reset() {
	b.TagBlock.Reset()
	b.FlowMeterBlock.Reset()
}

func (b *DocumentFlowBlock) ToInput(input proto.Input) proto.Input {
	input = b.TagBlock.ToInput(input)
	input = b.FlowMeterBlock.ToInput(input)
	return input
}

func (d *DocumentFlow) NewColumnBlock() ckdb.CKColumnBlock {
	return &DocumentFlowBlock{
		TagBlock:       d.Tag.NewColumnBlock().(*flow_metrics.TagBlock),
		FlowMeterBlock: d.FlowMeter.NewColumnBlock().(*flow_metrics.FlowMeterBlock),
	}
}

func (d *DocumentFlow) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*DocumentFlowBlock)
	d.Tag.AppendToColumnBlock(block.TagBlock, d.Timestamp)
	d.FlowMeter.AppendToColumnBlock(block.FlowMeterBlock)
}

type DocumentAppBlock struct {
	*flow_metrics.TagBlock
	*flow_metrics.AppMeterBlock
}

func (b *DocumentAppBlock) Reset() {
	b.TagBlock.Reset()
	b.AppMeterBlock.Reset()
}

func (b *DocumentAppBlock) ToInput(input proto.Input) proto.Input {
	input = b.TagBlock.ToInput(input)
	input = b.AppMeterBlock.ToInput(input)
	return input
}

func (d *DocumentApp) NewColumnBlock() ckdb.CKColumnBlock {
	return &DocumentAppBlock{
		TagBlock:      d.Tag.NewColumnBlock().(*flow_metrics.TagBlock),
		AppMeterBlock: d.AppMeter.NewColumnBlock().(*flow_metrics.AppMeterBlock),
	}
}

func (d *DocumentApp) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*DocumentAppBlock)
	d.Tag.AppendToColumnBlock(block.TagBlock, d.Timestamp)
	d.AppMeter.AppendToColumnBlock(block.AppMeterBlock)
}

type DocumentUsageBlock struct {
	*flow_metrics.TagBlock
	*flow_metrics.UsageMeterBlock
}

func (b *DocumentUsageBlock) Reset() {
	b.TagBlock.Reset()
	b.UsageMeterBlock.Reset()
}

func (b *DocumentUsageBlock) ToInput(input proto.Input) proto.Input {
	input = b.TagBlock.ToInput(input)
	input = b.UsageMeterBlock.ToInput(input)
	return input
}

func (d *DocumentUsage) NewColumnBlock() ckdb.CKColumnBlock {
	return &DocumentUsageBlock{
		TagBlock:        d.Tag.NewColumnBlock().(*flow_metrics.TagBlock),
		UsageMeterBlock: d.UsageMeter.NewColumnBlock().(*flow_metrics.UsageMeterBlock),
	}
}

func (d *DocumentUsage) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*DocumentUsageBlock)
	d.Tag.AppendToColumnBlock(block.TagBlock, d.Timestamp)
	d.UsageMeter.AppendToColumnBlock(block.UsageMeterBlock)
}
