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

type PodCluster struct {
	UpdaterBase[
		cloudmodel.PodCluster,
		*diffbase.PodCluster,
		*metadbmodel.PodCluster,
		metadbmodel.PodCluster,
		*message.AddedPodClusters,
		message.AddedPodClusters,
		message.AddNoneAddition,
		*message.UpdatedPodCluster,
		message.UpdatedPodCluster,
		*message.UpdatedPodClusterFields,
		message.UpdatedPodClusterFields,
		*message.DeletedPodClusters,
		message.DeletedPodClusters,
		message.DeleteNoneAddition]
}

func NewPodCluster(wholeCache *cache.Cache, cloudData []cloudmodel.PodCluster) *PodCluster {
	updater := &PodCluster{
		newUpdaterBase[
			cloudmodel.PodCluster,
			*diffbase.PodCluster,
			*metadbmodel.PodCluster,
			metadbmodel.PodCluster,
			*message.AddedPodClusters,
			message.AddedPodClusters,
			message.AddNoneAddition,
			*message.UpdatedPodCluster,
			message.UpdatedPodCluster,
			*message.UpdatedPodClusterFields,
			message.UpdatedPodClusterFields,
			*message.DeletedPodClusters,
			message.DeletedPodClusters,
			message.DeleteNoneAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN,
			wholeCache,
			db.NewPodCluster().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PodClusters,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (c *PodCluster) generateDBItemToAdd(cloudItem *cloudmodel.PodCluster) (*metadbmodel.PodCluster, bool) {
	vpcID, exists := c.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.Lcuuid,
		), c.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.PodCluster{
		Name:        cloudItem.Name,
		Version:     cloudItem.Version,
		ClusterName: cloudItem.ClusterName,
		SubDomain:   cloudItem.SubDomainLcuuid,
		Domain:      c.metadata.GetDomainLcuuid(),
		Region:      cloudItem.RegionLcuuid,
		AZ:          cloudItem.AZLcuuid,
		VPCID:       vpcID,
		UID:         ctrlrcommon.GenerateResourceShortUUID(ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN),
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (c *PodCluster) generateUpdateInfo(diffBase *diffbase.PodCluster, cloudItem *cloudmodel.PodCluster) (*message.UpdatedPodClusterFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedPodClusterFields)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.ClusterName != cloudItem.ClusterName {
		mapInfo["cluster_name"] = cloudItem.ClusterName
		structInfo.ClusterName.Set(diffBase.ClusterName, cloudItem.ClusterName)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	// if diffBase.AZLcuuid != cloudItem.AZLcuuid {
	// 	mapInfo["az"] = cloudItem.AZLcuuid
	// 	structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	// }

	return structInfo, mapInfo, len(mapInfo) > 0
}
