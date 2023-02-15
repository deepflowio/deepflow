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

type PodIngress struct {
	UpdaterBase[cloudmodel.PodIngress, mysql.PodIngress, *cache.PodIngress]
}

func NewPodIngress(wholeCache *cache.Cache, cloudData []cloudmodel.PodIngress) *PodIngress {
	updater := &PodIngress{
		UpdaterBase[cloudmodel.PodIngress, mysql.PodIngress, *cache.PodIngress]{
			cache:        wholeCache,
			dbOperator:   db.NewPodIngress(),
			diffBaseData: wholeCache.PodIngresses,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (i *PodIngress) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodIngress) (diffBase *cache.PodIngress, exists bool) {
	diffBase, exists = i.diffBaseData[cloudItem.Lcuuid]
	return
}

func (i *PodIngress) generateDBItemToAdd(cloudItem *cloudmodel.PodIngress) (*mysql.PodIngress, bool) {
	podNamespaceID, exists := i.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			common.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podClusterID, exists := i.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			common.RESOURCE_TYPE_POD_INGRESS_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.PodIngress{
		Name:           cloudItem.Name,
		PodNamespaceID: podNamespaceID,
		PodClusterID:   podClusterID,
		SubDomain:      cloudItem.SubDomainLcuuid,
		Domain:         i.cache.DomainLcuuid,
		Region:         cloudItem.RegionLcuuid,
		AZ:             cloudItem.AZLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (i *PodIngress) generateUpdateInfo(diffBase *cache.PodIngress, cloudItem *cloudmodel.PodIngress) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		updateInfo["az"] = cloudItem.AZLcuuid
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (i *PodIngress) addCache(dbItems []*mysql.PodIngress) {
	i.cache.AddPodIngresses(dbItems)
}

func (i *PodIngress) updateCache(cloudItem *cloudmodel.PodIngress, diffBase *cache.PodIngress) {
	diffBase.Update(cloudItem)
}

func (i *PodIngress) deleteCache(lcuuids []string) {
	i.cache.DeletePodIngresses(lcuuids)
}
