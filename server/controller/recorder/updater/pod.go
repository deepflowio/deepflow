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
)

type Pod struct {
	UpdaterBase[cloudmodel.Pod, mysql.Pod, *diffbase.Pod]
}

func NewPod(wholeCache *cache.Cache, cloudData []cloudmodel.Pod) *Pod {
	updater := &Pod{
		UpdaterBase[cloudmodel.Pod, mysql.Pod, *diffbase.Pod]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_POD_EN,
			cache:        wholeCache,
			dbOperator:   db.NewPod(),
			diffBaseData: wholeCache.DiffBaseDataSet.Pods,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *Pod) getDiffBaseByCloudItem(cloudItem *cloudmodel.Pod) (diffBase *diffbase.Pod, exists bool) {
	diffBase, exists = p.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *Pod) generateDBItemToAdd(cloudItem *cloudmodel.Pod) (*mysql.Pod, bool) {
	vpcID, exists := p.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podNamespaceID, exists := p.cache.ToolDataSet.GetPodNamespaceIDByLcuuid(cloudItem.PodNamespaceLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podClusterID, exists := p.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podGroupID, exists := p.cache.ToolDataSet.GetPodGroupIDByLcuuid(cloudItem.PodGroupLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.PodGroupLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	var podReplicaSetID int
	if cloudItem.PodReplicaSetLcuuid != "" {
		podReplicaSetID, exists = p.cache.ToolDataSet.GetPodReplicaSetIDByLcuuid(cloudItem.PodReplicaSetLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.PodReplicaSetLcuuid,
				ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
	}

	dbItem := &mysql.Pod{
		Name:            cloudItem.Name,
		Label:           cloudItem.Label,
		ENV:             cloudItem.ENV,
		ContainerIDs:    cloudItem.ContainerIDs,
		Annotation:      cloudItem.Annotation,
		State:           cloudItem.State,
		PodClusterID:    podClusterID,
		PodNamespaceID:  podNamespaceID,
		PodNodeID:       p.cache.ToolDataSet.GetPodNodeIDByLcuuid(cloudItem.PodNodeLcuuid),
		PodReplicaSetID: podReplicaSetID,
		PodGroupID:      podGroupID,
		SubDomain:       cloudItem.SubDomainLcuuid,
		Domain:          p.cache.DomainLcuuid,
		Region:          cloudItem.RegionLcuuid,
		AZ:              cloudItem.AZLcuuid,
		VPCID:           vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	if !cloudItem.CreatedAt.IsZero() {
		dbItem.CreatedAt = cloudItem.CreatedAt
	}
	return dbItem, true
}

func (p *Pod) generateUpdateInfo(diffBase *diffbase.Pod, cloudItem *cloudmodel.Pod) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := p.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		updateInfo["epc_id"] = vpcID
	}
	if diffBase.PodNodeLcuuid != cloudItem.PodNodeLcuuid {
		updateInfo["pod_node_id"] = p.cache.ToolDataSet.GetPodNodeIDByLcuuid(cloudItem.PodNodeLcuuid)
	}
	if diffBase.PodReplicaSetLcuuid != cloudItem.PodReplicaSetLcuuid {
		var podReplicaSetID int
		if cloudItem.PodReplicaSetLcuuid != "" {
			var exists bool
			podReplicaSetID, exists = p.cache.ToolDataSet.GetPodReplicaSetIDByLcuuid(cloudItem.PodReplicaSetLcuuid)
			if !exists {
				log.Errorf(resourceAForResourceBNotFound(
					ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.PodReplicaSetLcuuid,
					ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
				))
				return nil, false
			}
		}
		updateInfo["pod_rs_id"] = podReplicaSetID
	}
	if diffBase.PodGroupLcuuid != cloudItem.PodGroupLcuuid {
		podGroupID, exists := p.cache.ToolDataSet.GetPodGroupIDByLcuuid(cloudItem.PodGroupLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.PodGroupLcuuid,
				ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		updateInfo["pod_group_id"] = podGroupID
	}
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Label != cloudItem.Label {
		updateInfo["label"] = cloudItem.Label
	}
	if diffBase.Annotation != cloudItem.Annotation {
		updateInfo["annotation"] = cloudItem.Annotation
	}
	if diffBase.ENV != cloudItem.ENV {
		updateInfo["env"] = cloudItem.ENV
	}
	if diffBase.ContainerIDs != cloudItem.ContainerIDs {
		updateInfo["container_ids"] = cloudItem.ContainerIDs
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		updateInfo["az"] = cloudItem.AZLcuuid
	}
	if diffBase.State != cloudItem.State {
		updateInfo["state"] = cloudItem.State
	}
	if diffBase.CreatedAt != cloudItem.CreatedAt {
		updateInfo["created_at"] = cloudItem.CreatedAt
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
