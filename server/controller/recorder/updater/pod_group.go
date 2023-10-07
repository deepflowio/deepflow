/*
 * Copyright (c) 2023 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type PodGroup struct {
	UpdaterBase[cloudmodel.PodGroup, mysql.PodGroup, *cache.PodGroup]
}

func NewPodGroup(wholeCache *cache.Cache, cloudData []cloudmodel.PodGroup) *PodGroup {
	updater := &PodGroup{
		UpdaterBase[cloudmodel.PodGroup, mysql.PodGroup, *cache.PodGroup]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN,
			cache:        wholeCache,
			dbOperator:   db.NewPodGroup(),
			diffBaseData: wholeCache.PodGroups,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *PodGroup) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodGroup) (diffBase *cache.PodGroup, exists bool) {
	diffBase, exists = p.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *PodGroup) generateDBItemToAdd(cloudItem *cloudmodel.PodGroup) (*mysql.PodGroup, bool) {
	podNamespaceID, exists := p.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podClusterID, exists := p.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.PodGroup{
		Name:           cloudItem.Name,
		Type:           cloudItem.Type,
		Label:          cloudItem.Label,
		PodNum:         cloudItem.PodNum,
		PodNamespaceID: podNamespaceID,
		PodClusterID:   podClusterID,
		SubDomain:      cloudItem.SubDomainLcuuid,
		Domain:         p.cache.DomainLcuuid,
		Region:         cloudItem.RegionLcuuid,
		AZ:             cloudItem.AZLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (p *PodGroup) generateUpdateInfo(diffBase *cache.PodGroup, cloudItem *cloudmodel.PodGroup) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Type != cloudItem.Type {
		updateInfo["type"] = cloudItem.Type
	}
	if diffBase.PodNum != cloudItem.PodNum {
		updateInfo["pod_num"] = cloudItem.PodNum
	}
	if diffBase.Label != cloudItem.Label {
		updateInfo["label"] = cloudItem.Label
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
