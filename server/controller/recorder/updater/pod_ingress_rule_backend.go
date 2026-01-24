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

// PodIngressRuleBackendMessageFactory defines the message factory for PodIngressRuleBackend
type PodIngressRuleBackendMessageFactory struct{}

func (f *PodIngressRuleBackendMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedPodIngressRuleBackends{}
}

func (f *PodIngressRuleBackendMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedPodIngressRuleBackend{}
}

func (f *PodIngressRuleBackendMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedPodIngressRuleBackends{}
}

func (f *PodIngressRuleBackendMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedPodIngressRuleBackendFields{}
}

type PodIngressRuleBackend struct {
	UpdaterBase[
		cloudmodel.PodIngressRuleBackend,
		*diffbase.PodIngressRuleBackend,
		*metadbmodel.PodIngressRuleBackend,
		metadbmodel.PodIngressRuleBackend,
	]
}

func NewPodIngressRuleBackend(wholeCache *cache.Cache, cloudData []cloudmodel.PodIngressRuleBackend) *PodIngressRuleBackend {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, &PodIngressRuleBackendMessageFactory{})
	}

	updater := &PodIngressRuleBackend{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN,
			wholeCache,
			db.NewPodIngressRuleBackend().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PodIngressRuleBackends,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

// Implement DataGenerator interface

func (p *PodIngressRuleBackend) generateDBItemToAdd(cloudItem *cloudmodel.PodIngressRuleBackend) (*metadbmodel.PodIngressRuleBackend, bool) {
	podIngressRuleID, exists := p.cache.ToolDataSet.GetPodIngressRuleIDByLcuuid(cloudItem.PodIngressRuleLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, cloudItem.PodIngressRuleLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	podIngressID, exists := p.cache.ToolDataSet.GetPodIngressIDByLcuuid(cloudItem.PodIngressLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.PodIngressLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	podServiceID, exists := p.cache.ToolDataSet.GetPodServiceIDByLcuuid(cloudItem.PodServiceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.PodServiceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.PodIngressRuleBackend{
		Path:             cloudItem.Path,
		Port:             cloudItem.Port,
		PodServiceID:     podServiceID,
		PodIngressID:     podIngressID,
		PodIngressRuleID: podIngressRuleID,
		SubDomain:        cloudItem.SubDomainLcuuid,
		Domain:           p.metadata.GetDomainLcuuid(),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (p *PodIngressRuleBackend) generateUpdateInfo(diffBase *diffbase.PodIngressRuleBackend, cloudItem *cloudmodel.PodIngressRuleBackend) (types.UpdatedFields, map[string]interface{}, bool) {
	return nil, nil, false
}
