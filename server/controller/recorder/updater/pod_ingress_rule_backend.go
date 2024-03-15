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

type PodIngressRuleBackend struct {
	UpdaterBase[
		cloudmodel.PodIngressRuleBackend,
		mysql.PodIngressRuleBackend,
		*diffbase.PodIngressRuleBackend,
		*message.PodIngressRuleBackendAdd,
		message.PodIngressRuleBackendAdd,
		*message.PodIngressRuleBackendUpdate,
		message.PodIngressRuleBackendUpdate,
		*message.PodIngressRuleBackendFieldsUpdate,
		message.PodIngressRuleBackendFieldsUpdate,
		*message.PodIngressRuleBackendDelete,
		message.PodIngressRuleBackendDelete]
}

func NewPodIngressRuleBackend(wholeCache *cache.Cache, cloudData []cloudmodel.PodIngressRuleBackend) *PodIngressRuleBackend {
	updater := &PodIngressRuleBackend{
		newUpdaterBase[
			cloudmodel.PodIngressRuleBackend,
			mysql.PodIngressRuleBackend,
			*diffbase.PodIngressRuleBackend,
			*message.PodIngressRuleBackendAdd,
			message.PodIngressRuleBackendAdd,
			*message.PodIngressRuleBackendUpdate,
			message.PodIngressRuleBackendUpdate,
			*message.PodIngressRuleBackendFieldsUpdate,
			message.PodIngressRuleBackendFieldsUpdate,
			*message.PodIngressRuleBackendDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN,
			wholeCache,
			db.NewPodIngressRuleBackend().SetORG(wholeCache.GetORG()),
			wholeCache.DiffBaseDataSet.PodIngressRuleBackends,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (b *PodIngressRuleBackend) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodIngressRuleBackend) (diffBase *diffbase.PodIngressRuleBackend, exists bool) {
	diffBase, exists = b.diffBaseData[cloudItem.Lcuuid]
	return
}

func (b *PodIngressRuleBackend) generateDBItemToAdd(cloudItem *cloudmodel.PodIngressRuleBackend) (*mysql.PodIngressRuleBackend, bool) {
	podIngressRuleID, exists := b.cache.ToolDataSet.GetPodIngressRuleIDByLcuuid(cloudItem.PodIngressRuleLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, cloudItem.PodIngressRuleLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podIngressID, exists := b.cache.ToolDataSet.GetPodIngressIDByLcuuid(cloudItem.PodIngressLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.PodIngressLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podServiceID, exists := b.cache.ToolDataSet.GetPodServiceIDByLcuuid(cloudItem.PodServiceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.PodServiceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.PodIngressRuleBackend{
		Path:             cloudItem.Path,
		Port:             cloudItem.Port,
		PodServiceID:     podServiceID,
		PodIngressID:     podIngressID,
		PodIngressRuleID: podIngressRuleID,
		SubDomain:        cloudItem.SubDomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (b *PodIngressRuleBackend) generateUpdateInfo(diffBase *diffbase.PodIngressRuleBackend, cloudItem *cloudmodel.PodIngressRuleBackend) (*message.PodIngressRuleBackendFieldsUpdate, map[string]interface{}, bool) {
	return nil, nil, false
}
