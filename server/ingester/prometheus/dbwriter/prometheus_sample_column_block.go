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

package dbwriter

import (
	"github.com/ClickHouse/ch-go/proto"

	"github.com/deepflowio/deepflow/server/libs/ckdb"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
)

type PrometheusSampleMiniBlock struct {
	AppLabelLen         int
	ColTime             proto.ColDateTime
	ColMetricId         proto.ColUInt32
	ColTargetId         proto.ColUInt32
	ColTeamId           proto.ColUInt16
	ColAppLabelValueIds [ckdb.MAX_APP_LABEL_COLUMN_INDEX + 1]proto.ColUInt32
	ColValue            proto.ColFloat64
}

func (b *PrometheusSampleMiniBlock) Reset() {
	b.ColTime.Reset()
	b.ColMetricId.Reset()
	b.ColTargetId.Reset()
	b.ColTeamId.Reset()
	for i := 1; i < b.AppLabelLen; i++ {
		b.ColAppLabelValueIds[i].Reset()
	}
	b.ColValue.Reset()
}

func (b *PrometheusSampleMiniBlock) ToInput(input proto.Input) proto.Input {
	input = append(input,
		proto.InputColumn{Name: ckdb.COLUMN_TIME, Data: &b.ColTime},
		proto.InputColumn{Name: ckdb.COLUMN_METRIC_ID, Data: &b.ColMetricId},
		proto.InputColumn{Name: ckdb.COLUMN_TARGET_ID, Data: &b.ColTargetId},
		proto.InputColumn{Name: ckdb.COLUMN_TEAM_ID, Data: &b.ColTeamId},
		proto.InputColumn{Name: ckdb.COLUMN_VALUE, Data: &b.ColValue},
	)
	for i := 1; i < b.AppLabelLen; i++ {
		input = append(input, proto.InputColumn{Name: ckdb.COLUMN_APP_LABEL_VALUE_IDs[i], Data: &b.ColAppLabelValueIds[i]})
	}
	return input
}

func (n *PrometheusSampleMini) NewColumnBlock() ckdb.CKColumnBlock {
	return &PrometheusSampleMiniBlock{
		AppLabelLen: n.AppLabelLen(),
	}
}

func (n *PrometheusSampleMini) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*PrometheusSampleMiniBlock)
	ckdb.AppendColDateTime(&block.ColTime, n.Timestamp)
	block.ColMetricId.Append(n.MetricID)
	block.ColTargetId.Append(n.TargetID)
	block.ColTeamId.Append(n.TeamID)
	appLabelLen := n.AppLabelLen()
	if block.AppLabelLen < appLabelLen {
		block.AppLabelLen = appLabelLen
	}
	for i := 1; i < block.AppLabelLen; i++ {
		block.ColAppLabelValueIds[i].Append(n.AppLabelValueIDs[i])
	}
	block.ColValue.Append(n.Value)
}

type PrometheusSampleBlock struct {
	*PrometheusSampleMiniBlock
	*flow_metrics.UniversalTagBlock
}

func (b *PrometheusSampleBlock) Reset() {
	b.PrometheusSampleMiniBlock.Reset()
	b.UniversalTagBlock.Reset()
}

func (b *PrometheusSampleBlock) ToInput(input proto.Input) proto.Input {
	input = b.PrometheusSampleMiniBlock.ToInput(input)
	return b.UniversalTagBlock.ToInput(input)
}

func (n *PrometheusSample) NewColumnBlock() ckdb.CKColumnBlock {
	return &PrometheusSampleBlock{
		PrometheusSampleMiniBlock: n.PrometheusSampleMini.NewColumnBlock().(*PrometheusSampleMiniBlock),
		UniversalTagBlock:         n.UniversalTag.NewColumnBlock().(*flow_metrics.UniversalTagBlock),
	}
}

func (n *PrometheusSample) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*PrometheusSampleBlock)
	n.PrometheusSampleMini.AppendToColumnBlock(block.PrometheusSampleMiniBlock)
	n.UniversalTag.AppendToColumnBlock(block.UniversalTagBlock)
}
