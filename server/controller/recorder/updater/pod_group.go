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

type PodGroup struct {
	UpdaterBase[cloudmodel.PodGroup, mysql.PodGroup, *diffbase.PodGroup]
}

func NewPodGroup(wholeCache *cache.Cache, cloudData []cloudmodel.PodGroup) *PodGroup {
	updater := &PodGroup{
		UpdaterBase[cloudmodel.PodGroup, mysql.PodGroup, *diffbase.PodGroup]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN,
			cache:        wholeCache,
			dbOperator:   db.NewPodGroup(),
			diffBaseData: wholeCache.DiffBaseDataSet.PodGroups,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *PodGroup) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodGroup) (diffBase *diffbase.PodGroup, exists bool) {
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

func (p *PodGroup) generateUpdateInfo(diffBase *diffbase.PodGroup, cloudItem *cloudmodel.PodGroup) (interface{}, map[string]interface{}, bool) {
	structInfo := new(message.PodGroupFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.Type != cloudItem.Type {
		mapInfo["type"] = cloudItem.Type
		structInfo.Type.Set(diffBase.Type, cloudItem.Type)
	}
	if diffBase.PodNum != cloudItem.PodNum {
		mapInfo["pod_num"] = cloudItem.PodNum
		structInfo.PodNum.Set(diffBase.PodNum, cloudItem.PodNum)
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
