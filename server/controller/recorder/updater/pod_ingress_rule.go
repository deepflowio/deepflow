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

// PodIngressRuleMessageFactory defines the message factory for PodIngressRule
type PodIngressRuleMessageFactory struct{}

func (f *PodIngressRuleMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedPodIngressRules{}
}

func (f *PodIngressRuleMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedPodIngressRule{}
}

func (f *PodIngressRuleMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedPodIngressRules{}
}

func (f *PodIngressRuleMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedPodIngressRuleFields{}
}

type PodIngressRule struct {
	UpdaterBase[
		cloudmodel.PodIngressRule,
		*diffbase.PodIngressRule,
		*metadbmodel.PodIngressRule,
		metadbmodel.PodIngressRule,
	]
}

func NewPodIngressRule(wholeCache *cache.Cache, cloudData []cloudmodel.PodIngressRule) *PodIngressRule {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, &PodIngressRuleMessageFactory{})
	}

	updater := &PodIngressRule{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN,
			wholeCache,
			db.NewPodIngressRule().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PodIngressRules,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

// Implement DataGenerator interface

func (p *PodIngressRule) generateDBItemToAdd(cloudItem *cloudmodel.PodIngressRule) (*metadbmodel.PodIngressRule, bool) {
	podIngressID, exists := p.cache.ToolDataSet.GetPodIngressIDByLcuuid(cloudItem.PodIngressLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.PodIngressLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.PodIngressRule{
		Name:         cloudItem.Name,
		Protocol:     cloudItem.Protocol,
		Host:         cloudItem.Host,
		PodIngressID: podIngressID,
		SubDomain:    cloudItem.SubDomainLcuuid,
		Domain:       p.metadata.GetDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (p *PodIngressRule) generateUpdateInfo(diffBase *diffbase.PodIngressRule, cloudItem *cloudmodel.PodIngressRule) (types.UpdatedFields, map[string]interface{}, bool) {
	return nil, nil, false
}
