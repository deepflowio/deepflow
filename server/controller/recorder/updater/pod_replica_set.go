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
)

type PodReplicaSet struct {
	UpdaterBase[
		cloudmodel.PodReplicaSet,
		*diffbase.PodReplicaSet,
		*metadbmodel.PodReplicaSet,
		metadbmodel.PodReplicaSet,
		*message.AddedPodReplicaSets,
		message.AddedPodReplicaSets,
		message.AddNoneAddition,
		*message.UpdatedPodReplicaSet,
		message.UpdatedPodReplicaSet,
		*message.UpdatedPodReplicaSetFields,
		message.UpdatedPodReplicaSetFields,
		*message.DeletedPodReplicaSets,
		message.DeletedPodReplicaSets,
		message.DeleteNoneAddition]
}

func NewPodReplicaSet(wholeCache *cache.Cache, cloudData []cloudmodel.PodReplicaSet) *PodReplicaSet {
	updater := &PodReplicaSet{
		newUpdaterBase[
			cloudmodel.PodReplicaSet,
			*diffbase.PodReplicaSet,
			*metadbmodel.PodReplicaSet,
			metadbmodel.PodReplicaSet,
			*message.AddedPodReplicaSets,
			message.AddedPodReplicaSets,
			message.AddNoneAddition,
			*message.UpdatedPodReplicaSet,
			message.UpdatedPodReplicaSet,
			*message.UpdatedPodReplicaSetFields,
			message.UpdatedPodReplicaSetFields,
			*message.DeletedPodReplicaSets,
			message.DeletedPodReplicaSets,
			message.DeleteNoneAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN,
			wholeCache,
			db.NewPodReplicaSet().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PodReplicaSets,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (r *PodReplicaSet) generateDBItemToAdd(cloudItem *cloudmodel.PodReplicaSet) (*metadbmodel.PodReplicaSet, bool) {
	podNamespaceID, exists := r.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.Lcuuid,
		), r.metadata.LogPrefixes)
		return nil, false
	}
	podClusterID, exists := r.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.Lcuuid,
		), r.metadata.LogPrefixes)
		return nil, false
	}
	podGroupID, exists := r.cache.ToolDataSet.GetPodGroupIDByLcuuid(cloudItem.PodGroupLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.PodGroupLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.Lcuuid,
		), r.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.PodReplicaSet{
		Name:           cloudItem.Name,
		Label:          cloudItem.Label,
		PodClusterID:   podClusterID,
		PodGroupID:     podGroupID,
		PodNamespaceID: podNamespaceID,
		PodNum:         cloudItem.PodNum,
		SubDomain:      cloudItem.SubDomainLcuuid,
		Domain:         r.metadata.GetDomainLcuuid(),
		Region:         cloudItem.RegionLcuuid,
		AZ:             cloudItem.AZLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (r *PodReplicaSet) generateUpdateInfo(diffBase *diffbase.PodReplicaSet, cloudItem *cloudmodel.PodReplicaSet) (*message.UpdatedPodReplicaSetFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedPodReplicaSetFields)
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
	// if diffBase.AZLcuuid != cloudItem.AZLcuuid {
	// 	mapInfo["az"] = cloudItem.AZLcuuid
	// 	structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	// }
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
