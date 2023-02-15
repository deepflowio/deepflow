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

type PodIngressRule struct {
	UpdaterBase[cloudmodel.PodIngressRule, mysql.PodIngressRule, *cache.PodIngressRule]
}

func NewPodIngressRule(wholeCache *cache.Cache, cloudData []cloudmodel.PodIngressRule) *PodIngressRule {
	updater := &PodIngressRule{
		UpdaterBase[cloudmodel.PodIngressRule, mysql.PodIngressRule, *cache.PodIngressRule]{
			cache:        wholeCache,
			dbOperator:   db.NewPodIngressRule(),
			diffBaseData: wholeCache.PodIngressRules,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (r *PodIngressRule) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodIngressRule) (diffBase *cache.PodIngressRule, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *PodIngressRule) generateDBItemToAdd(cloudItem *cloudmodel.PodIngressRule) (*mysql.PodIngressRule, bool) {
	podIngressID, exists := r.cache.ToolDataSet.GetPodIngressIDByLcuuid(cloudItem.PodIngressLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.PodIngressLcuuid,
			common.RESOURCE_TYPE_POD_INGRESS_RULE_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}

	dbItem := &mysql.PodIngressRule{
		Name:         cloudItem.Name,
		Protocol:     cloudItem.Protocol,
		Host:         cloudItem.Host,
		PodIngressID: podIngressID,
		SubDomain:    cloudItem.SubDomainLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

// 保留接口
func (r *PodIngressRule) generateUpdateInfo(diffBase *cache.PodIngressRule, cloudItem *cloudmodel.PodIngressRule) (map[string]interface{}, bool) {
	return nil, false
}

func (b *PodIngressRule) addCache(dbItems []*mysql.PodIngressRule) {
	b.cache.AddPodIngressRules(dbItems)
}

// 保留接口
func (b *PodIngressRule) updateCache(cloudItem *cloudmodel.PodIngressRule, diffBase *cache.PodIngressRule) {
}

func (b *PodIngressRule) deleteCache(lcuuids []string) {
	b.cache.DeletePodIngressRules(lcuuids)
}
