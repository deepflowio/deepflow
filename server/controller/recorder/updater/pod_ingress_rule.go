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

type PodIngressRule struct {
	UpdaterBase[
		cloudmodel.PodIngressRule,
		mysql.PodIngressRule,
		*diffbase.PodIngressRule,
		*message.PodIngressRuleAdd,
		message.PodIngressRuleAdd,
		*message.PodIngressRuleUpdate,
		message.PodIngressRuleUpdate,
		*message.PodIngressRuleFieldsUpdate,
		message.PodIngressRuleFieldsUpdate,
		*message.PodIngressRuleDelete,
		message.PodIngressRuleDelete]
}

func NewPodIngressRule(wholeCache *cache.Cache, cloudData []cloudmodel.PodIngressRule) *PodIngressRule {
	updater := &PodIngressRule{
		newUpdaterBase[
			cloudmodel.PodIngressRule,
			mysql.PodIngressRule,
			*diffbase.PodIngressRule,
			*message.PodIngressRuleAdd,
			message.PodIngressRuleAdd,
			*message.PodIngressRuleUpdate,
			message.PodIngressRuleUpdate,
			*message.PodIngressRuleFieldsUpdate,
			message.PodIngressRuleFieldsUpdate,
			*message.PodIngressRuleDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN,
			wholeCache,
			db.NewPodIngressRule().SetORG(wholeCache.GetORG()),
			wholeCache.DiffBaseDataSet.PodIngressRules,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (r *PodIngressRule) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodIngressRule) (diffBase *diffbase.PodIngressRule, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *PodIngressRule) generateDBItemToAdd(cloudItem *cloudmodel.PodIngressRule) (*mysql.PodIngressRule, bool) {
	podIngressID, exists := r.cache.ToolDataSet.GetPodIngressIDByLcuuid(cloudItem.PodIngressLcuuid)
	if !exists {
		log.Error(r.org.LogPre(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.PodIngressLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_RULE_EN, cloudItem.Lcuuid,
		)))
		return nil, false
	}

	dbItem := &mysql.PodIngressRule{
		Name:         cloudItem.Name,
		Protocol:     cloudItem.Protocol,
		Host:         cloudItem.Host,
		PodIngressID: podIngressID,
		SubDomain:    cloudItem.SubDomainLcuuid,
		Domain:       r.cache.DomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (r *PodIngressRule) generateUpdateInfo(diffBase *diffbase.PodIngressRule, cloudItem *cloudmodel.PodIngressRule) (*message.PodIngressRuleFieldsUpdate, map[string]interface{}, bool) {
	return nil, nil, false
}
