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

type NATRule struct {
	UpdaterBase[
		cloudmodel.NATRule,
		mysql.NATRule,
		*diffbase.NATRule,
		*message.NATRuleAdd,
		message.NATRuleAdd,
		*message.NATRuleUpdate,
		message.NATRuleUpdate,
		*message.NATRuleFieldsUpdate,
		message.NATRuleFieldsUpdate,
		*message.NATRuleDelete,
		message.NATRuleDelete]
}

func NewNATRule(wholeCache *cache.Cache, cloudData []cloudmodel.NATRule) *NATRule {
	updater := &NATRule{
		newUpdaterBase[
			cloudmodel.NATRule,
			mysql.NATRule,
			*diffbase.NATRule,
			*message.NATRuleAdd,
			message.NATRuleAdd,
			*message.NATRuleUpdate,
			message.NATRuleUpdate,
			*message.NATRuleFieldsUpdate,
			message.NATRuleFieldsUpdate,
			*message.NATRuleDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN,
			wholeCache,
			db.NewNATRule().SetORG(wholeCache.GetORG()),
			wholeCache.DiffBaseDataSet.NATRules,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (r *NATRule) getDiffBaseByCloudItem(cloudItem *cloudmodel.NATRule) (diffBase *diffbase.NATRule, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *NATRule) generateDBItemToAdd(cloudItem *cloudmodel.NATRule) (*mysql.NATRule, bool) {
	var natGatewayID int
	var exists bool
	if cloudItem.NATGatewayLcuuid != "" {
		natGatewayID, exists = r.cache.ToolDataSet.GetNATGatewayIDByLcuuid(cloudItem.NATGatewayLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, cloudItem.NATGatewayLcuuid,
				ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
	}
	var vinterfaceID int
	if cloudItem.VInterfaceLcuuid != "" {
		vinterfaceID, exists = r.cache.ToolDataSet.GetVInterfaceIDByLcuuid(cloudItem.VInterfaceLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.VInterfaceLcuuid,
				ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
	}

	dbItem := &mysql.NATRule{
		NATGatewayID:   natGatewayID,
		VInterfaceID:   vinterfaceID,
		Type:           cloudItem.Type,
		Protocol:       cloudItem.Protocol,
		FloatingIP:     cloudItem.FloatingIP,
		FloatingIPPort: cloudItem.FloatingIPPort,
		FixedIP:        cloudItem.FixedIP,
		FixedIPPort:    cloudItem.FixedIPPort,
		Domain:         r.cache.DomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (r *NATRule) generateUpdateInfo(diffBase *diffbase.NATRule, cloudItem *cloudmodel.NATRule) (*message.NATRuleFieldsUpdate, map[string]interface{}, bool) {
	return nil, nil, false
}
