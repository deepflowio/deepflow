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

type PodNamespace struct {
	UpdaterBase[cloudmodel.PodNamespace, mysql.PodNamespace, *cache.PodNamespace]
}

func NewPodNamespace(wholeCache *cache.Cache, cloudData []cloudmodel.PodNamespace) *PodNamespace {
	updater := &PodNamespace{
		UpdaterBase[cloudmodel.PodNamespace, mysql.PodNamespace, *cache.PodNamespace]{
			cache:        wholeCache,
			dbOperator:   db.NewPodNamespace(),
			diffBaseData: wholeCache.PodNamespaces,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (n *PodNamespace) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodNamespace) (diffBase *cache.PodNamespace, exists bool) {
	diffBase, exists = n.diffBaseData[cloudItem.Lcuuid]
	return
}

func (n *PodNamespace) generateDBItemToAdd(cloudItem *cloudmodel.PodNamespace) (*mysql.PodNamespace, bool) {
	podClusterID, exists := n.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			common.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			common.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.PodNamespace{
		Name:         cloudItem.Name,
		PodClusterID: podClusterID,
		SubDomain:    cloudItem.SubDomainLcuuid,
		Domain:       n.cache.DomainLcuuid,
		Region:       cloudItem.RegionLcuuid,
		AZ:           cloudItem.AZLcuuid,
		CloudTags:    cloudItem.CloudTags,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (n *PodNamespace) generateUpdateInfo(diffBase *cache.PodNamespace, cloudItem *cloudmodel.PodNamespace) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		updateInfo["az"] = cloudItem.AZLcuuid
	}
	if diffBase.CloudTags != cloudItem.CloudTags {
		updateInfo["cloud_tags"] = cloudItem.CloudTags
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}

func (n *PodNamespace) addCache(dbItems []*mysql.PodNamespace) {
	n.cache.AddPodNamespaces(dbItems)
}

func (n *PodNamespace) updateCache(cloudItem *cloudmodel.PodNamespace, diffBase *cache.PodNamespace) {
	diffBase.Update(cloudItem)
}

func (n *PodNamespace) deleteCache(lcuuids []string) {
	n.cache.DeletePodNamespaces(lcuuids)
}
