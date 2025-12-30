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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type NATRule struct {
	UpdaterBase[
		cloudmodel.NATRule,
		*diffbase.NATRule,
		*metadbmodel.NATRule,
		metadbmodel.NATRule,
		*message.AddedNATRules,
		message.AddedNATRules,
		message.AddNoneAddition,
		*message.UpdatedNATRule,
		message.UpdatedNATRule,
		*message.UpdatedNATRuleFields,
		message.UpdatedNATRuleFields,
		*message.DeletedNATRules,
		message.DeletedNATRules,
		message.DeleteNoneAddition]
}

func NewNATRule(wholeCache *cache.Cache, cloudData []cloudmodel.NATRule) *NATRule {
	updater := &NATRule{
		newUpdaterBase[
			cloudmodel.NATRule,
			*diffbase.NATRule,
			*metadbmodel.NATRule,
			metadbmodel.NATRule,
			*message.AddedNATRules,
			message.AddedNATRules,
			message.AddNoneAddition,
			*message.UpdatedNATRule,
			message.UpdatedNATRule,
			*message.UpdatedNATRuleFields,
			message.UpdatedNATRuleFields,
			*message.DeletedNATRules,
			message.DeletedNATRules,
			message.DeleteNoneAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN,
			wholeCache,
			db.NewNATRule().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.NATRules,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (r *NATRule) generateDBItemToAdd(cloudItem *cloudmodel.NATRule) (*metadbmodel.NATRule, bool) {
	var natGatewayID int
	var exists bool
	if cloudItem.NATGatewayLcuuid != "" {
		natGatewayID, exists = r.cache.ToolDataSet.GetNATGatewayIDByLcuuid(cloudItem.NATGatewayLcuuid)
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN, cloudItem.NATGatewayLcuuid,
				ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN, cloudItem.Lcuuid,
			), r.metadata.LogPrefixes)
			return nil, false
		}
	}
	var vinterfaceID int
	if cloudItem.VInterfaceLcuuid != "" {
		vinterfaceID, exists = r.cache.ToolDataSet.GetVInterfaceIDByLcuuid(cloudItem.VInterfaceLcuuid)
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.VInterfaceLcuuid,
				ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN, cloudItem.Lcuuid,
			), r.metadata.LogPrefixes)
			return nil, false
		}
	}

	dbItem := &metadbmodel.NATRule{
		NATGatewayID:   natGatewayID,
		VInterfaceID:   vinterfaceID,
		Type:           cloudItem.Type,
		Protocol:       cloudItem.Protocol,
		FloatingIP:     cloudItem.FloatingIP,
		FloatingIPPort: cloudItem.FloatingIPPort,
		FixedIP:        cloudItem.FixedIP,
		FixedIPPort:    cloudItem.FixedIPPort,
		Domain:         r.metadata.GetDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (r *NATRule) generateUpdateInfo(diffBase *diffbase.NATRule, cloudItem *cloudmodel.NATRule) (*message.UpdatedNATRuleFields, map[string]interface{}, bool) {
	return nil, nil, false
}
