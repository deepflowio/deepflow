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
	"encoding/json"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type PodNamespace struct {
	UpdaterBase[
		cloudmodel.PodNamespace,
		*diffbase.PodNamespace,
		*metadbmodel.PodNamespace,
		metadbmodel.PodNamespace,
		*message.AddedPodNamespaces,
		message.AddedPodNamespaces,
		message.AddNoneAddition,
		*message.UpdatedPodNamespace,
		message.UpdatedPodNamespace,
		*message.UpdatedPodNamespaceFields,
		message.UpdatedPodNamespaceFields,
		*message.DeletedPodNamespaces,
		message.DeletedPodNamespaces,
		message.DeleteNoneAddition]
}

func NewPodNamespace(wholeCache *cache.Cache, cloudData []cloudmodel.PodNamespace) *PodNamespace {
	updater := &PodNamespace{
		newUpdaterBase[
			cloudmodel.PodNamespace,
			*diffbase.PodNamespace,
			*metadbmodel.PodNamespace,
			metadbmodel.PodNamespace,
			*message.AddedPodNamespaces,
			message.AddedPodNamespaces,
			message.AddNoneAddition,
			*message.UpdatedPodNamespace,
			message.UpdatedPodNamespace,
			*message.UpdatedPodNamespaceFields,
			message.UpdatedPodNamespaceFields,
			*message.DeletedPodNamespaces,
			message.DeletedPodNamespaces,
			message.DeleteNoneAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN,
			wholeCache,
			db.NewPodNamespace().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PodNamespaces,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (n *PodNamespace) generateDBItemToAdd(cloudItem *cloudmodel.PodNamespace) (*metadbmodel.PodNamespace, bool) {
	podClusterID, exists := n.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.Lcuuid,
		), n.metadata.LogPrefixes)
		return nil, false
	}
	cloudTags := map[string]string{}
	if cloudItem.CloudTags != nil {
		cloudTags = cloudItem.CloudTags
	}
	dbItem := &metadbmodel.PodNamespace{
		Name:             cloudItem.Name,
		PodClusterID:     podClusterID,
		SubDomain:        cloudItem.SubDomainLcuuid,
		Domain:           n.metadata.GetDomainLcuuid(),
		Region:           cloudItem.RegionLcuuid,
		AZ:               cloudItem.AZLcuuid,
		LearnedCloudTags: cloudTags,
		CustomCloudTags:  make(map[string]string),
		UID:              ctrlrcommon.GenerateResourceShortUUID(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (n *PodNamespace) generateUpdateInfo(diffBase *diffbase.PodNamespace, cloudItem *cloudmodel.PodNamespace) (*message.UpdatedPodNamespaceFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedPodNamespaceFields)
	mapInfo := make(map[string]interface{})
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	// if diffBase.AZLcuuid != cloudItem.AZLcuuid {
	// 	mapInfo["az"] = cloudItem.AZLcuuid
	// 	structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	// }
	if cloudcommon.DiffMap(diffBase.LearnedCloudTags, cloudItem.CloudTags) {
		updateTags := map[string]string{}
		if cloudItem.CloudTags != nil {
			updateTags = cloudItem.CloudTags
		}
		tagsJson, _ := json.Marshal(updateTags)
		mapInfo["learned_cloud_tags"] = tagsJson
		structInfo.LearnedCloudTags.Set(diffBase.LearnedCloudTags, cloudItem.CloudTags)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
