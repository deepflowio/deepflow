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
package flow_tag

import (
	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type AppServiceTagBlock struct {
	ColTime        proto.ColDateTime
	ColTable       *proto.ColLowCardinality[string]
	ColAppService  *proto.ColLowCardinality[string]
	ColAppInstance *proto.ColLowCardinality[string]
	ColTeamId      proto.ColUInt16
}

func (b *AppServiceTagBlock) Reset() {
	b.ColTime.Reset()
	b.ColTable.Reset()
	b.ColAppService.Reset()
	b.ColAppInstance.Reset()
	b.ColTeamId.Reset()
}

func (b *AppServiceTagBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_TIME, Data: &b.ColTime},
		proto.InputColumn{Name: ckdb.COLUMN_TABLE, Data: b.ColTable},
		proto.InputColumn{Name: ckdb.COLUMN_APP_SERVICE, Data: b.ColAppService},
		proto.InputColumn{Name: ckdb.COLUMN_APP_INSTANCE, Data: b.ColAppInstance},
		proto.InputColumn{Name: ckdb.COLUMN_TEAM_ID, Data: &b.ColTeamId},
	)
}

func (n *AppServiceTag) NewColumnBlock() ckdb.CKColumnBlock {
	return &AppServiceTagBlock{
		ColTable:       new(proto.ColStr).LowCardinality(),
		ColAppService:  new(proto.ColStr).LowCardinality(),
		ColAppInstance: new(proto.ColStr).LowCardinality(),
	}
}

func (n *AppServiceTag) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*AppServiceTagBlock)
	ckdb.AppendColDateTime(&block.ColTime, n.Time)
	block.ColTable.Append(n.Table)
	block.ColAppService.Append(n.AppService)
	block.ColAppInstance.Append(n.AppInstance)
	block.ColTeamId.Append(n.TeamID)
}
