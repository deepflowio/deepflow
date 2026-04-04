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
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
)

// NATRuleMessageFactory NATRule资源的消息工厂
type NATRuleMessageFactory struct{}

func (f *NATRuleMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedNatRules{}
}

func (f *NATRuleMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedNatRule{}
}

func (f *NATRuleMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedNatRules{}
}

func (f *NATRuleMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedNatRuleFields{}
}

type NATRule struct {
	UpdaterBase[
		cloudmodel.NATRule,
		*diffbase.NatRule,
		*metadbmodel.NATRule,
		metadbmodel.NATRule,
	]
}

func NewNATRule(wholeCache *cache.Cache, cloudData []cloudmodel.NATRule) *NATRule {
	updater := &NATRule{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN,
			wholeCache,
			db.NewNATRule().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBases().NATRule().GetAll(),
			cloudData,
		),
	}
	updater.setDataGenerator(updater)

	if !hasMessageFactory(updater.resourceType) {
		RegisterMessageFactory(updater.resourceType, &NATRuleMessageFactory{})
	}

	return updater
}

func (r *NATRule) generateDBItemToAdd(cloudItem *cloudmodel.NATRule) (*metadbmodel.NATRule, bool) {
	var natGatewayID int
	var exists bool
	if cloudItem.NATGatewayLcuuid != "" {
		natGatewayItem := r.cache.Tool().NatGateway().GetByLcuuid(cloudItem.NATGatewayLcuuid)
		natGatewayID, exists = natGatewayItem.Id(), natGatewayItem.IsValid()
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
		vinterfaceItem := r.cache.Tool().Vinterface().GetByLcuuid(cloudItem.VInterfaceLcuuid)
		vinterfaceID, exists = vinterfaceItem.Id(), vinterfaceItem.IsValid()
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
func (r *NATRule) generateUpdateInfo(diffBase *diffbase.NatRule, cloudItem *cloudmodel.NATRule) (types.UpdatedFields, map[string]interface{}, bool) {
	return nil, nil, false
}
