/*
 * Copyright (c) 2022 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type SecurityGroupRule struct {
	UpdaterBase[cloudmodel.SecurityGroupRule, mysql.SecurityGroupRule, *cache.SecurityGroupRule]
}

func NewSecurityGroupRule(wholeCache *cache.Cache, cloudData []cloudmodel.SecurityGroupRule) *SecurityGroupRule {
	updater := &SecurityGroupRule{
		UpdaterBase[cloudmodel.SecurityGroupRule, mysql.SecurityGroupRule, *cache.SecurityGroupRule]{
			cache:        wholeCache,
			dbOperator:   db.NewSecurityGroupRule(),
			diffBaseData: wholeCache.SecurityGroupRules,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (r *SecurityGroupRule) getDiffBaseByCloudItem(cloudItem *cloudmodel.SecurityGroupRule) (diffBase *cache.SecurityGroupRule, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *SecurityGroupRule) generateDBItemToAdd(cloudItem *cloudmodel.SecurityGroupRule) (*mysql.SecurityGroupRule, bool) {
	securityGroupID, exists := r.cache.ToolDataSet.GetSecurityGroupIDByLcuuid(cloudItem.SecurityGroupLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_SECURITY_GROUP_EN, cloudItem.SecurityGroupLcuuid,
			common.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN, cloudItem.Lcuuid,
		))
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
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *SecurityGroupRule) generateUpdateInfo(diffBase *cache.SecurityGroupRule, cloudItem *cloudmodel.SecurityGroupRule) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Priority != cloudItem.Priority {
		updateInfo["priority"] = cloudItem.Priority
	}
	if diffBase.EtherType != cloudItem.EtherType {
		updateInfo["ethertype"] = cloudItem.EtherType
	}
	if diffBase.RemotePortRange != cloudItem.RemotePortRange {
		updateInfo["remote_port_range"] = cloudItem.RemotePortRange
	}
	if diffBase.Local != cloudItem.Local {
		updateInfo["local"] = cloudItem.Local
	}
	if diffBase.Remote != cloudItem.Remote {
		updateInfo["remote"] = cloudItem.Remote
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (r *SecurityGroupRule) addCache(dbItems []*mysql.SecurityGroupRule) {
	r.cache.AddSecurityGroupRules(dbItems)
}

func (r *SecurityGroupRule) updateCache(cloudItem *cloudmodel.SecurityGroupRule, diffBase *cache.SecurityGroupRule) {
	diffBase.Update(cloudItem)
}

func (r *SecurityGroupRule) deleteCache(lcuuids []string) {
	r.cache.DeleteSecurityGroupRules(lcuuids)
}
