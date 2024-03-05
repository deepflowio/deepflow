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

type Pod struct {
	UpdaterBase[
		cloudmodel.Pod,
		mysql.Pod,
		*diffbase.Pod,
		*message.PodAdd,
		message.PodAdd,
		*message.PodUpdate,
		message.PodUpdate,
		*message.PodFieldsUpdate,
		message.PodFieldsUpdate,
		*message.PodDelete,
		message.PodDelete]
}

func NewPod(wholeCache *cache.Cache, cloudData []cloudmodel.Pod) *Pod {
	updater := &Pod{
		newUpdaterBase[
			cloudmodel.Pod,
			mysql.Pod,
			*diffbase.Pod,
			*message.PodAdd,
			message.PodAdd,
			*message.PodUpdate,
			message.PodUpdate,
			*message.PodFieldsUpdate,
			message.PodFieldsUpdate,
			*message.PodDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_EN,
			wholeCache,
			db.NewPod(),
			wholeCache.DiffBaseDataSet.Pods,
			cloudData,
		),
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
	podServiceID, exists := p.cache.ToolDataSet.GetPodServiceIDByLcuuid(cloudItem.PodServiceLcuuid)
	if !exists {
		log.Infof(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.PodServiceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
		))
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
		PodServiceID:    podServiceID,
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

func (p *Pod) generateUpdateInfo(diffBase *diffbase.Pod, cloudItem *cloudmodel.Pod) (*message.PodFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.PodFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := p.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
			))
			return nil, nil, false
		}
		mapInfo["epc_id"] = vpcID
		structInfo.VPCID.SetNew(vpcID) // TODO is old value needed?
		structInfo.VPCLcuuid.Set(diffBase.VPCLcuuid, cloudItem.VPCLcuuid)
	}
	if diffBase.PodNodeLcuuid != cloudItem.PodNodeLcuuid {
		podNodeID := p.cache.ToolDataSet.GetPodNodeIDByLcuuid(cloudItem.PodNodeLcuuid) // TODO need to log not found error
		mapInfo["pod_node_id"] = podNodeID
		structInfo.PodNodeID.SetNew(podNodeID)
		structInfo.PodNodeLcuuid.Set(diffBase.PodNodeLcuuid, cloudItem.PodNodeLcuuid)
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
				return nil, nil, false
			}
		}
		mapInfo["pod_rs_id"] = podReplicaSetID
		structInfo.PodReplicaSetID.SetNew(podReplicaSetID)
		structInfo.PodReplicaSetLcuuid.Set(diffBase.PodReplicaSetLcuuid, cloudItem.PodReplicaSetLcuuid)
	}
	if diffBase.PodGroupLcuuid != cloudItem.PodGroupLcuuid {
		podGroupID, exists := p.cache.ToolDataSet.GetPodGroupIDByLcuuid(cloudItem.PodGroupLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.PodGroupLcuuid,
				ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
			))
			return nil, nil, false
		}
		mapInfo["pod_group_id"] = podGroupID
		structInfo.PodGroupID.SetNew(podGroupID)
		structInfo.PodGroupLcuuid.Set(diffBase.PodGroupLcuuid, cloudItem.PodGroupLcuuid)
	}
	if diffBase.PodServiceLcuuid != cloudItem.PodServiceLcuuid {
		podServiceID, exists := p.cache.ToolDataSet.GetPodServiceIDByLcuuid(cloudItem.PodServiceLcuuid)
		if !exists {
			log.Infof(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.PodServiceLcuuid,
				ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
			))
		}
		mapInfo["pod_service_id"] = podServiceID
		structInfo.PodServiceID.SetNew(podServiceID)
		structInfo.PodServiceLcuuid.Set(diffBase.PodServiceLcuuid, cloudItem.PodServiceLcuuid)
	}
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}
	if diffBase.Annotation != cloudItem.Annotation {
		mapInfo["annotation"] = cloudItem.Annotation
		structInfo.Annotation.Set(diffBase.Annotation, cloudItem.Annotation)
	}
	if diffBase.ENV != cloudItem.ENV {
		mapInfo["env"] = cloudItem.ENV
		structInfo.ENV.Set(diffBase.ENV, cloudItem.ENV)
	}
	if diffBase.ContainerIDs != cloudItem.ContainerIDs {
		mapInfo["container_ids"] = cloudItem.ContainerIDs
		structInfo.ContainerIDs.Set(diffBase.ContainerIDs, cloudItem.ContainerIDs)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	}
	if diffBase.State != cloudItem.State {
		mapInfo["state"] = cloudItem.State
		structInfo.State.Set(diffBase.State, cloudItem.State)
	}
	if diffBase.CreatedAt != cloudItem.CreatedAt {
		mapInfo["created_at"] = cloudItem.CreatedAt
		structInfo.CreatedAt.Set(diffBase.CreatedAt, cloudItem.CreatedAt)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
