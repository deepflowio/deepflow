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
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type PodCluster struct {
	UpdaterBase[
		cloudmodel.PodCluster,
		mysql.PodCluster,
		*diffbase.PodCluster,
		*message.PodClusterAdd,
		message.PodClusterAdd,
		*message.PodClusterUpdate,
		message.PodClusterUpdate,
		*message.PodClusterFieldsUpdate,
		message.PodClusterFieldsUpdate,
		*message.PodClusterDelete,
		message.PodClusterDelete]
}

func NewPodCluster(wholeCache *cache.Cache, cloudData []cloudmodel.PodCluster) *PodCluster {
	updater := &PodCluster{
		newUpdaterBase[
			cloudmodel.PodCluster,
			mysql.PodCluster,
			*diffbase.PodCluster,
			*message.PodClusterAdd,
			message.PodClusterAdd,
			*message.PodClusterUpdate,
			message.PodClusterUpdate,
			*message.PodClusterFieldsUpdate,
			message.PodClusterFieldsUpdate,
			*message.PodClusterDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN,
			wholeCache,
			db.NewPodCluster(),
			wholeCache.DiffBaseDataSet.PodClusters,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (c *PodCluster) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodCluster) (diffBase *diffbase.PodCluster, exists bool) {
	diffBase, exists = c.diffBaseData[cloudItem.Lcuuid]
	return
}

func (c *PodCluster) generateDBItemToAdd(cloudItem *cloudmodel.PodCluster) (*mysql.PodCluster, bool) {
	vpcID, exists := c.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.PodCluster{
		Name:        cloudItem.Name,
		Version:     cloudItem.Version,
		ClusterName: cloudItem.ClusterName,
		SubDomain:   cloudItem.SubDomainLcuuid,
		Domain:      c.cache.DomainLcuuid,
		Region:      cloudItem.RegionLcuuid,
		AZ:          cloudItem.AZLcuuid,
		VPCID:       vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (c *PodCluster) generateUpdateInfo(diffBase *diffbase.PodCluster, cloudItem *cloudmodel.PodCluster) (*message.PodClusterFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.PodClusterFieldsUpdate)
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
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
