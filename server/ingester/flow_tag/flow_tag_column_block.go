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

type FlowTagBlock struct {
	TagType
	ColTime           proto.ColDateTime
	ColTable          *proto.ColLowCardinality[string]
	ColVpcId          proto.ColInt32
	ColPodNsId        proto.ColUInt16
	ColFieldType      *proto.ColLowCardinality[string]
	ColFieldName      *proto.ColLowCardinality[string]
	ColFieldValueType *proto.ColLowCardinality[string]
	ColTeamId         proto.ColUInt16
	ColFieldValue     proto.ColStr
	ColCount          proto.ColUInt64
}

func (b *FlowTagBlock) Reset() {
	b.ColTime.Reset()
	b.ColTable.Reset()
	b.ColVpcId.Reset()
	b.ColPodNsId.Reset()
	b.ColFieldType.Reset()
	b.ColFieldName.Reset()
	b.ColFieldValueType.Reset()
	b.ColTeamId.Reset()
	b.ColFieldValue.Reset()
	b.ColCount.Reset()
}

func (b *FlowTagBlock) ToInput(input proto.Input) proto.Input {
	input = append(input,
		proto.InputColumn{Name: ckdb.COLUMN_TIME, Data: &b.ColTime},
		proto.InputColumn{Name: ckdb.COLUMN_TABLE, Data: b.ColTable},
		proto.InputColumn{Name: ckdb.COLUMN_VPC_ID, Data: &b.ColVpcId},
		proto.InputColumn{Name: ckdb.COLUMN_POD_NS_ID, Data: &b.ColPodNsId},
		proto.InputColumn{Name: ckdb.COLUMN_FIELD_TYPE, Data: b.ColFieldType},
		proto.InputColumn{Name: ckdb.COLUMN_FIELD_NAME, Data: b.ColFieldName},
		proto.InputColumn{Name: ckdb.COLUMN_FIELD_VALUE_TYPE, Data: b.ColFieldValueType},
		proto.InputColumn{Name: ckdb.COLUMN_TEAM_ID, Data: &b.ColTeamId},
	)
	if b.TagType == TagFieldValue {
		input = append(input,
			proto.InputColumn{Name: ckdb.COLUMN_FIELD_VALUE, Data: &b.ColFieldValue},
			proto.InputColumn{Name: ckdb.COLUMN_COUNT, Data: &b.ColCount})
	}
	return input
}

func (n *FlowTag) NewColumnBlock() ckdb.CKColumnBlock {
	return &FlowTagBlock{
		TagType:           n.TagType,
		ColTable:          new(proto.ColStr).LowCardinality(),
		ColFieldType:      new(proto.ColStr).LowCardinality(),
		ColFieldName:      new(proto.ColStr).LowCardinality(),
		ColFieldValueType: new(proto.ColStr).LowCardinality(),
	}
}

func (n *FlowTag) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*FlowTagBlock)

	fieldValueType := n.FieldValueType
	if fieldValueType == FieldValueTypeAuto {
		fieldValueType = FieldValueTypeString
		if len(n.FieldValue) == 0 && n.FieldType != FieldTag {
			fieldValueType = FieldValueTypeFloat
		}
	}
	ckdb.AppendColDateTime(&block.ColTime, n.Timestamp)
	block.ColTable.Append(n.Table)
	block.ColVpcId.Append(n.VpcId)
	block.ColPodNsId.Append(n.PodNsId)
	block.ColFieldType.Append(n.FieldType.String())
	block.ColFieldName.Append(n.FieldName)
	block.ColFieldValueType.Append(fieldValueType.String())
	block.ColTeamId.Append(n.TeamID)
	if n.TagType == TagFieldValue {
		block.ColFieldValue.Append(n.FieldValue)
		block.ColCount.Append(uint64(1))
	}
}
