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

package updater

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type SecurityGroupRule struct {
	UpdaterBase[
		cloudmodel.SecurityGroupRule,
		mysql.SecurityGroupRule,
		*diffbase.SecurityGroupRule,
		*message.SecurityGroupRuleAdd,
		message.SecurityGroupRuleAdd,
		*message.SecurityGroupRuleUpdate,
		message.SecurityGroupRuleUpdate,
		*message.SecurityGroupRuleFieldsUpdate,
		message.SecurityGroupRuleFieldsUpdate,
		*message.SecurityGroupRuleDelete,
		message.SecurityGroupRuleDelete]
}

func NewSecurityGroupRule(wholeCache *cache.Cache, cloudData []cloudmodel.SecurityGroupRule) *SecurityGroupRule {
	updater := &SecurityGroupRule{
		newUpdaterBase[
			cloudmodel.SecurityGroupRule,
			mysql.SecurityGroupRule,
			*diffbase.SecurityGroupRule,
			*message.SecurityGroupRuleAdd,
			message.SecurityGroupRuleAdd,
			*message.SecurityGroupRuleUpdate,
			message.SecurityGroupRuleUpdate,
			*message.SecurityGroupRuleFieldsUpdate,
			message.SecurityGroupRuleFieldsUpdate,
			*message.SecurityGroupRuleDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN,
			wholeCache,
			db.NewSecurityGroupRule().SetORG(wholeCache.GetORG()),
			wholeCache.DiffBaseDataSet.SecurityGroupRules,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (r *SecurityGroupRule) getDiffBaseByCloudItem(cloudItem *cloudmodel.SecurityGroupRule) (diffBase *diffbase.SecurityGroupRule, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *SecurityGroupRule) generateDBItemToAdd(cloudItem *cloudmodel.SecurityGroupRule) (*mysql.SecurityGroupRule, bool) {
	securityGroupID, exists := r.cache.ToolDataSet.GetSecurityGroupIDByLcuuid(cloudItem.SecurityGroupLcuuid)
	if !exists {
		log.Error(r.org.LogPre(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_EN, cloudItem.SecurityGroupLcuuid,
			ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN, cloudItem.Lcuuid,
		)))
		return nil, false
	}

	dbItem := &mysql.SecurityGroupRule{
		SecurityGroupID: securityGroupID,
		Direction:       cloudItem.Direction,
		EtherType:       cloudItem.EtherType,
		Protocol:        cloudItem.Protocol,
		Priority:        cloudItem.Priority,
		LocalPortRange:  cloudItem.LocalPortRange,
		RemotePortRange: cloudItem.RemotePortRange,
		Local:           cloudItem.Local,
		Remote:          cloudItem.Remote,
		Action:          cloudItem.Action,
		Domain:          r.cache.DomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *SecurityGroupRule) generateUpdateInfo(diffBase *diffbase.SecurityGroupRule, cloudItem *cloudmodel.SecurityGroupRule) (*message.SecurityGroupRuleFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.SecurityGroupRuleFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Priority != cloudItem.Priority {
		mapInfo["priority"] = cloudItem.Priority
		structInfo.Priority.Set(diffBase.Priority, cloudItem.Priority)
	}
	if diffBase.EtherType != cloudItem.EtherType {
		mapInfo["ethertype"] = cloudItem.EtherType
		structInfo.EtherType.Set(diffBase.EtherType, cloudItem.EtherType)
	}
	if diffBase.RemotePortRange != cloudItem.RemotePortRange {
		mapInfo["remote_port_range"] = cloudItem.RemotePortRange
		structInfo.RemotePortRange.Set(diffBase.RemotePortRange, cloudItem.RemotePortRange)
	}
	if diffBase.Local != cloudItem.Local {
		mapInfo["local"] = cloudItem.Local
		structInfo.Local.Set(diffBase.Local, cloudItem.Local)
	}
	if diffBase.Remote != cloudItem.Remote {
		mapInfo["remote"] = cloudItem.Remote
		structInfo.Remote.Set(diffBase.Remote, cloudItem.Remote)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
