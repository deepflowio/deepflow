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
)

type AlertEventBlock struct {
	ColTime             proto.ColDateTime
	ColId               proto.ColUInt64
	ColPolicyId         proto.ColUInt32
	ColPolicyType       proto.ColUInt8
	ColAlertPolicy      *proto.ColLowCardinality[string]
	ColMetricValue      proto.ColFloat64
	ColMetricValueStr   proto.ColStr
	ColEventLevel       proto.ColUInt8
	ColTargetTags       proto.ColStr
	ColTagStringNames   *proto.ColArr[string]
	ColTagStringValues  *proto.ColArr[string]
	ColTagIntNames      *proto.ColArr[string]
	ColTagIntValues     *proto.ColArr[int64]
	ColTriggerThreshold *proto.ColLowCardinality[string]
	ColMetricUnit       *proto.ColLowCardinality[string]
	ColTargetUid        proto.ColStr
	ColQueryRegion      *proto.ColLowCardinality[string]
	ColTeamId           proto.ColUInt16
	ColUserId           proto.ColUInt32
}

func (b *AlertEventBlock) Reset() {
	b.ColTime.Reset()
	b.ColId.Reset()
	b.ColPolicyId.Reset()
	b.ColPolicyType.Reset()
	b.ColAlertPolicy.Reset()
	b.ColMetricValue.Reset()
	b.ColMetricValueStr.Reset()
	b.ColEventLevel.Reset()
	b.ColTargetTags.Reset()
	b.ColTagStringNames.Reset()
	b.ColTagStringValues.Reset()
	b.ColTagIntNames.Reset()
	b.ColTagIntValues.Reset()
	b.ColTriggerThreshold.Reset()
	b.ColMetricUnit.Reset()
	b.ColTargetUid.Reset()
	b.ColQueryRegion.Reset()
	b.ColTeamId.Reset()
	b.ColUserId.Reset()
}

func (b *AlertEventBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_TIME, Data: &b.ColTime},
		proto.InputColumn{Name: ckdb.COLUMN__ID, Data: &b.ColId},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_ID, Data: &b.ColPolicyId},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_TYPE, Data: &b.ColPolicyType},
		proto.InputColumn{Name: ckdb.COLUMN_ALERT_POLICY, Data: b.ColAlertPolicy},
		proto.InputColumn{Name: ckdb.COLUMN_METRIC_VALUE, Data: &b.ColMetricValue},
		proto.InputColumn{Name: ckdb.COLUMN_METRIC_VALUE_STR, Data: &b.ColMetricValueStr},
		proto.InputColumn{Name: ckdb.COLUMN_EVENT_LEVEL, Data: &b.ColEventLevel},
		proto.InputColumn{Name: ckdb.COLUMN_TARGET_TAGS, Data: &b.ColTargetTags},
		proto.InputColumn{Name: ckdb.COLUMN_TAG_STRING_NAMES, Data: b.ColTagStringNames},
		proto.InputColumn{Name: ckdb.COLUMN_TAG_STRING_VALUES, Data: b.ColTagStringValues},
		proto.InputColumn{Name: ckdb.COLUMN_TAG_INT_NAMES, Data: b.ColTagIntNames},
		proto.InputColumn{Name: ckdb.COLUMN_TAG_INT_VALUES, Data: b.ColTagIntValues},
		proto.InputColumn{Name: ckdb.COLUMN_TRIGGER_THRESHOLD, Data: b.ColTriggerThreshold},
		proto.InputColumn{Name: ckdb.COLUMN_METRIC_UNIT, Data: b.ColMetricUnit},
		proto.InputColumn{Name: ckdb.COLUMN__TARGET_UID, Data: &b.ColTargetUid},
		proto.InputColumn{Name: ckdb.COLUMN__QUERY_REGION, Data: b.ColQueryRegion},
		proto.InputColumn{Name: ckdb.COLUMN_TEAM_ID, Data: &b.ColTeamId},
		proto.InputColumn{Name: ckdb.COLUMN_USER_ID, Data: &b.ColUserId},
	)
}

func (n *AlertEventStore) NewColumnBlock() ckdb.CKColumnBlock {
	return &AlertEventBlock{
		ColAlertPolicy:      new(proto.ColStr).LowCardinality(),
		ColQueryRegion:      new(proto.ColStr).LowCardinality(),
		ColTagStringNames:   new(proto.ColStr).LowCardinality().Array(),
		ColTagStringValues:  new(proto.ColStr).Array(),
		ColTagIntNames:      new(proto.ColStr).LowCardinality().Array(),
		ColTagIntValues:     new(proto.ColInt64).Array(),
		ColTriggerThreshold: new(proto.ColStr).LowCardinality(),
		ColMetricUnit:       new(proto.ColStr).LowCardinality(),
	}
}

func (n *AlertEventStore) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*AlertEventBlock)
	ckdb.AppendColDateTime(&block.ColTime, n.Time)
	block.ColId.Append(n._id)
	block.ColPolicyId.Append(n.PolicyId)
	block.ColPolicyType.Append(n.PolicyType)
	block.ColAlertPolicy.Append(n.AlertPolicy)
	block.ColMetricValue.Append(n.MetricValue)
	block.ColMetricValueStr.Append(n.MetricValueStr)
	block.ColEventLevel.Append(n.EventLevel)
	block.ColTargetTags.Append(n.TargetTags)
	block.ColTagStringNames.Append(n.TagStrKeys)
	block.ColTagStringValues.Append(n.TagStrValues)
	block.ColTagIntNames.Append(n.TagIntKeys)
	block.ColTagIntValues.Append(n.TagIntValues)
	block.ColTriggerThreshold.Append(n.TriggerThreshold)
	block.ColMetricUnit.Append(n.MetricUnit)
	block.ColTargetUid.Append(n.XTargetUid)
	block.ColQueryRegion.Append(n.XQueryRegion)
	block.ColTeamId.Append(n.TeamID)
	block.ColUserId.Append(n.UserId)
}
