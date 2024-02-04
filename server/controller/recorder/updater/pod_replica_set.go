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

type PodReplicaSet struct {
	UpdaterBase[cloudmodel.PodReplicaSet, mysql.PodReplicaSet, *diffbase.PodReplicaSet]
}

func NewPodReplicaSet(wholeCache *cache.Cache, cloudData []cloudmodel.PodReplicaSet) *PodReplicaSet {
	updater := &PodReplicaSet{
		UpdaterBase[cloudmodel.PodReplicaSet, mysql.PodReplicaSet, *diffbase.PodReplicaSet]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN,
			cache:        wholeCache,
			dbOperator:   db.NewPodReplicaSet(),
			diffBaseData: wholeCache.DiffBaseDataSet.PodReplicaSets,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (r *PodReplicaSet) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodReplicaSet) (diffBase *diffbase.PodReplicaSet, exists bool) {
	diffBase, exists = r.diffBaseData[cloudItem.Lcuuid]
	return
}

func (r *PodReplicaSet) generateDBItemToAdd(cloudItem *cloudmodel.PodReplicaSet) (*mysql.PodReplicaSet, bool) {
	podNamespaceID, exists := r.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podClusterID, exists := r.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podGroupID, exists := r.cache.ToolDataSet.GetPodGroupIDByLcuuid(cloudItem.PodGroupLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.PodGroupLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.PodReplicaSet{
		Name:           cloudItem.Name,
		Label:          cloudItem.Label,
		PodClusterID:   podClusterID,
		PodGroupID:     podGroupID,
		PodNamespaceID: podNamespaceID,
		PodNum:         cloudItem.PodNum,
		SubDomain:      cloudItem.SubDomainLcuuid,
		Domain:         r.cache.DomainLcuuid,
		Region:         cloudItem.RegionLcuuid,
		AZ:             cloudItem.AZLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *PodReplicaSet) generateUpdateInfo(diffBase *diffbase.PodReplicaSet, cloudItem *cloudmodel.PodReplicaSet) (interface{}, map[string]interface{}, bool) {
	structInfo := new(message.PodReplicaSetFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.PodNum != cloudItem.PodNum {
		mapInfo["pod_num"] = cloudItem.PodNum
		structInfo.PodNum.Set(diffBase.PodNum, cloudItem.PodNum)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
