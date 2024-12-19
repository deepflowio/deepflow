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

type AlarmEventBlock struct {
	ColTime                    proto.ColDateTime
	ColId                      proto.ColUInt64
	ColLccuid                  proto.ColStr
	ColUser                    *proto.ColLowCardinality[string]
	ColUserId                  proto.ColUInt32
	ColPolicyId                proto.ColUInt32
	ColPolicyName              *proto.ColLowCardinality[string]
	ColPolicyLevel             proto.ColUInt32
	ColPolicyAppType           proto.ColUInt32
	ColPolicySubType           proto.ColUInt32
	ColPolicyContrastType      proto.ColUInt32
	ColPolicyDataLevel         *proto.ColLowCardinality[string]
	ColPolicyTargetUid         proto.ColStr
	ColPolicyTargetName        proto.ColStr
	ColPolicyGoTo              proto.ColStr
	ColPolicyTargetField       proto.ColStr
	ColPolicyEndpoints         *proto.ColLowCardinality[string]
	ColTriggerCondition        proto.ColStr
	ColTriggerValue            proto.ColFloat64
	ColValueUnit               *proto.ColLowCardinality[string]
	ColEventLevel              proto.ColUInt32
	ColAlarmTarget             *proto.ColLowCardinality[string]
	ColRegionId                proto.ColUInt16
	ColPolicyQueryUrl          proto.ColStr
	ColPolicyQueryConditions   proto.ColStr
	ColPolicyThresholdCritical proto.ColStr
	ColPolicyThresholdError    proto.ColStr
	ColPolicyThresholdWarning  proto.ColStr
	ColTeamId                  proto.ColUInt16
}

func (b *AlarmEventBlock) Reset() {
	b.ColTime.Reset()
	b.ColId.Reset()
	b.ColLccuid.Reset()
	b.ColUser.Reset()
	b.ColUserId.Reset()
	b.ColPolicyId.Reset()
	b.ColPolicyName.Reset()
	b.ColPolicyLevel.Reset()
	b.ColPolicyAppType.Reset()
	b.ColPolicySubType.Reset()
	b.ColPolicyContrastType.Reset()
	b.ColPolicyDataLevel.Reset()
	b.ColPolicyTargetUid.Reset()
	b.ColPolicyTargetName.Reset()
	b.ColPolicyGoTo.Reset()
	b.ColPolicyTargetField.Reset()
	b.ColPolicyEndpoints.Reset()
	b.ColTriggerCondition.Reset()
	b.ColTriggerValue.Reset()
	b.ColValueUnit.Reset()
	b.ColEventLevel.Reset()
	b.ColAlarmTarget.Reset()
	b.ColRegionId.Reset()
	b.ColPolicyQueryUrl.Reset()
	b.ColPolicyQueryConditions.Reset()
	b.ColPolicyThresholdCritical.Reset()
	b.ColPolicyThresholdError.Reset()
	b.ColPolicyThresholdWarning.Reset()
	b.ColTeamId.Reset()
}

func (b *AlarmEventBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_TIME, Data: &b.ColTime},
		proto.InputColumn{Name: ckdb.COLUMN__ID, Data: &b.ColId},
		proto.InputColumn{Name: ckdb.COLUMN_LCCUID, Data: &b.ColLccuid},
		proto.InputColumn{Name: ckdb.COLUMN_USER, Data: b.ColUser},
		proto.InputColumn{Name: ckdb.COLUMN_USER_ID, Data: &b.ColUserId},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_ID, Data: &b.ColPolicyId},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_NAME, Data: b.ColPolicyName},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_LEVEL, Data: &b.ColPolicyLevel},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_APP_TYPE, Data: &b.ColPolicyAppType},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_SUB_TYPE, Data: &b.ColPolicySubType},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_CONTRAST_TYPE, Data: &b.ColPolicyContrastType},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_DATA_LEVEL, Data: b.ColPolicyDataLevel},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_TARGET_UID, Data: &b.ColPolicyTargetUid},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_TARGET_NAME, Data: &b.ColPolicyTargetName},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_GO_TO, Data: &b.ColPolicyGoTo},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_TARGET_FIELD, Data: &b.ColPolicyTargetField},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_ENDPOINTS, Data: b.ColPolicyEndpoints},
		proto.InputColumn{Name: ckdb.COLUMN_TRIGGER_CONDITION, Data: &b.ColTriggerCondition},
		proto.InputColumn{Name: ckdb.COLUMN_TRIGGER_VALUE, Data: &b.ColTriggerValue},
		proto.InputColumn{Name: ckdb.COLUMN_VALUE_UNIT, Data: b.ColValueUnit},
		proto.InputColumn{Name: ckdb.COLUMN_EVENT_LEVEL, Data: &b.ColEventLevel},
		proto.InputColumn{Name: ckdb.COLUMN_ALARM_TARGET, Data: b.ColAlarmTarget},
		proto.InputColumn{Name: ckdb.COLUMN_REGION_ID, Data: &b.ColRegionId},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_QUERY_URL, Data: &b.ColPolicyQueryUrl},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_QUERY_CONDITIONS, Data: &b.ColPolicyQueryConditions},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_THRESHOLD_CRITICAL, Data: &b.ColPolicyThresholdCritical},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_THRESHOLD_ERROR, Data: &b.ColPolicyThresholdError},
		proto.InputColumn{Name: ckdb.COLUMN_POLICY_THRESHOLD_WARNING, Data: &b.ColPolicyThresholdWarning},
		proto.InputColumn{Name: ckdb.COLUMN_TEAM_ID, Data: &b.ColTeamId},
	)
}

func (n *AlarmEventStore) NewColumnBlock() ckdb.CKColumnBlock {
	return &AlarmEventBlock{
		ColUser:            new(proto.ColStr).LowCardinality(),
		ColPolicyName:      new(proto.ColStr).LowCardinality(),
		ColPolicyDataLevel: new(proto.ColStr).LowCardinality(),
		ColPolicyEndpoints: new(proto.ColStr).LowCardinality(),
		ColValueUnit:       new(proto.ColStr).LowCardinality(),
		ColAlarmTarget:     new(proto.ColStr).LowCardinality(),
	}
}

func (n *AlarmEventStore) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*AlarmEventBlock)
	ckdb.AppendColDateTime(&block.ColTime, n.Time)
	block.ColId.Append(n._id)
	block.ColLccuid.Append(n.Lcuuid)
	block.ColUser.Append(n.User)
	block.ColUserId.Append(n.UserId)
	block.ColPolicyId.Append(n.PolicyId)
	block.ColPolicyName.Append(n.PolicyName)
	block.ColPolicyLevel.Append(n.PolicyLevel)
	block.ColPolicyAppType.Append(n.PolicyAppType)
	block.ColPolicySubType.Append(n.PolicySubType)
	block.ColPolicyContrastType.Append(n.PolicyContrastType)
	block.ColPolicyDataLevel.Append(n.PolicyDataLevel)
	block.ColPolicyTargetUid.Append(n.PolicyTargetUid)
	block.ColPolicyTargetName.Append(n.PolicyTargetName)
	block.ColPolicyGoTo.Append(n.PolicyGoTo)
	block.ColPolicyTargetField.Append(n.PolicyTargetField)
	block.ColPolicyEndpoints.Append(n.PolicyEndpoints)
	block.ColTriggerCondition.Append(n.TriggerCondition)
	block.ColTriggerValue.Append(n.TriggerValue)
	block.ColValueUnit.Append(n.ValueUnit)
	block.ColEventLevel.Append(n.EventLevel)
	block.ColAlarmTarget.Append(n.AlarmTarget)
	block.ColRegionId.Append(n.RegionId)
	block.ColPolicyQueryUrl.Append(n.PolicyQueryUrl)
	block.ColPolicyQueryConditions.Append(n.PolicyQueryConditions)
	block.ColPolicyThresholdCritical.Append(n.PolicyThresholdCritical)
	block.ColPolicyThresholdError.Append(n.PolicyThresholdError)
	block.ColPolicyThresholdWarning.Append(n.PolicyThresholdWarning)
	block.ColTeamId.Append(n.TeamID)
}
