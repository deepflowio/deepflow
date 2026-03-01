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
	"time"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
	"github.com/deepflowio/deepflow/server/controller/recorder/statsd"
)

// PodMessageFactory defines the message factory for Pod
type PodMessageFactory struct{}

func (f *PodMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedPods{}
}

func (f *PodMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedPod{}
}

func (f *PodMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedPods{}
}

func (f *PodMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedPodFields{}
}

type Pod struct {
	UpdaterBase[
		cloudmodel.Pod,
		*diffbase.Pod,
		*metadbmodel.Pod,
		metadbmodel.Pod,
	]
}

func NewPod(wholeCache *cache.Cache, cloudData []cloudmodel.Pod) *Pod {
	updater := &Pod{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_POD_EN,
			wholeCache,
			db.NewPod().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBases().Pod().GetAll(),
			cloudData,
		),
	}
	updater.setDataGenerator(updater)

	if !hasMessageFactory(updater.resourceType) {
		RegisterMessageFactory(updater.resourceType, &PodMessageFactory{})
	}

	return updater
}

// Implement DataGenerator interface
func (p *Pod) generateDBItemToAdd(cloudItem *cloudmodel.Pod) (*metadbmodel.Pod, bool) {
	vpcItem := p.cache.Tool().Vpc().GetByLcuuid(cloudItem.VPCLcuuid)
	vpcID, exists := vpcItem.Id(), vpcItem.IsValid()
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	podNamespaceItem := p.cache.Tool().PodNamespace().GetByLcuuid(cloudItem.PodNamespaceLcuuid)
	podNamespaceID, exists := podNamespaceItem.Id(), podNamespaceItem.IsValid()
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN, cloudItem.PodNamespaceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	podClusterItem := p.cache.Tool().PodCluster().GetByLcuuid(cloudItem.PodClusterLcuuid)
	podClusterID, exists := podClusterItem.Id(), podClusterItem.IsValid()
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	podGroupItem := p.cache.Tool().PodGroup().GetByLcuuid(cloudItem.PodGroupLcuuid)
	podGroupID, exists := podGroupItem.Id(), podGroupItem.IsValid()
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.PodGroupLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	var podServiceID int
	if cloudItem.PodServiceLcuuid != "" {
		podServiceItem := p.cache.Tool().PodService().GetByLcuuid(cloudItem.PodServiceLcuuid)
		podServiceID, exists = podServiceItem.Id(), podServiceItem.IsValid()
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.PodServiceLcuuid,
				ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
			), p.metadata.LogPrefixes)
			return nil, false
		}
	}
	var podReplicaSetID int
	if cloudItem.PodReplicaSetLcuuid != "" {
		podReplicaSetItem := p.cache.Tool().PodReplicaSet().GetByLcuuid(cloudItem.PodReplicaSetLcuuid)
		podReplicaSetID, exists = podReplicaSetItem.Id(), podReplicaSetItem.IsValid()
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.PodReplicaSetLcuuid,
				ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
			), p.metadata.LogPrefixes)
			return nil, false
		}
	}

	dbItem := &metadbmodel.Pod{
		Name:            cloudItem.Name,
		Label:           cloudItem.Label,
		UID:             ctrlrcommon.GenerateResourceShortUUID(ctrlrcommon.RESOURCE_TYPE_POD_EN),
		ENV:             cloudItem.ENV,
		ContainerIDs:    cloudItem.ContainerIDs,
		Annotation:      cloudItem.Annotation,
		State:           cloudItem.State,
		PodClusterID:    podClusterID,
		PodNamespaceID:  podNamespaceID,
		PodNodeID:       p.cache.Tool().PodNode().GetByLcuuid(cloudItem.PodNodeLcuuid).Id(),
		PodReplicaSetID: podReplicaSetID,
		PodGroupID:      podGroupID,
		PodServiceID:    podServiceID,
		SubDomain:       cloudItem.SubDomainLcuuid,
		Domain:          p.metadata.GetDomainLcuuid(),
		Region:          cloudItem.RegionLcuuid,
		AZ:              cloudItem.AZLcuuid,
		VPCID:           vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	if !cloudItem.CreatedAt.IsZero() {
		dbItem.CreatedAt = cloudItem.CreatedAt
		p.recordStatsd(cloudItem)
	}
	return dbItem, true
}

func (p *Pod) recordStatsd(cloudItem *cloudmodel.Pod) {
	syncDelay := time.Since(cloudItem.CreatedAt).Seconds()
	p.statsd.GetMonitor(statsd.TagTypePodSyncDelay).Fill(int(syncDelay))
}

func (p *Pod) generateUpdateInfo(diffBase *diffbase.Pod, cloudItem *cloudmodel.Pod) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedPodFields)
	mapInfo := make(map[string]interface{})
	if diffBase.VpcLcuuid != cloudItem.VPCLcuuid {
		vpcItem := p.cache.Tool().Vpc().GetByLcuuid(cloudItem.VPCLcuuid)
		vpcID, exists := vpcItem.Id(), vpcItem.IsValid()
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
			), p.metadata.LogPrefixes)
			return nil, nil, false
		}
		mapInfo["epc_id"] = vpcID
		structInfo.VpcId.SetNew(vpcID) // TODO is old value needed?
		structInfo.VpcLcuuid.Set(diffBase.VpcLcuuid, cloudItem.VPCLcuuid)
	}
	if diffBase.PodNodeLcuuid != cloudItem.PodNodeLcuuid {
		podNodeID := p.cache.Tool().PodNode().GetByLcuuid(cloudItem.PodNodeLcuuid).Id() // TODO need to log not found error
		mapInfo["pod_node_id"] = podNodeID
		structInfo.PodNodeId.SetNew(podNodeID)
		structInfo.PodNodeLcuuid.Set(diffBase.PodNodeLcuuid, cloudItem.PodNodeLcuuid)
	}
	if diffBase.PodReplicaSetLcuuid != cloudItem.PodReplicaSetLcuuid {
		var podReplicaSetID int
		if cloudItem.PodReplicaSetLcuuid != "" {
			var exists bool
			podReplicaSetItem := p.cache.Tool().PodReplicaSet().GetByLcuuid(cloudItem.PodReplicaSetLcuuid)
			podReplicaSetID, exists = podReplicaSetItem.Id(), podReplicaSetItem.IsValid()
			if !exists {
				log.Error(resourceAForResourceBNotFound(
					ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN, cloudItem.PodReplicaSetLcuuid,
					ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
				), p.metadata.LogPrefixes)
				return nil, nil, false
			}
		}
		mapInfo["pod_rs_id"] = podReplicaSetID
		structInfo.PodReplicaSetId.SetNew(podReplicaSetID)
		structInfo.PodReplicaSetLcuuid.Set(diffBase.PodReplicaSetLcuuid, cloudItem.PodReplicaSetLcuuid)
	}
	if diffBase.PodGroupLcuuid != cloudItem.PodGroupLcuuid {
		podGroupItem := p.cache.Tool().PodGroup().GetByLcuuid(cloudItem.PodGroupLcuuid)
		podGroupID, exists := podGroupItem.Id(), podGroupItem.IsValid()
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN, cloudItem.PodGroupLcuuid,
				ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
			), p.metadata.LogPrefixes)
			return nil, nil, false
		}
		mapInfo["pod_group_id"] = podGroupID
		structInfo.PodGroupId.SetNew(podGroupID)
		structInfo.PodGroupLcuuid.Set(diffBase.PodGroupLcuuid, cloudItem.PodGroupLcuuid)
	}
	if diffBase.PodServiceLcuuid != cloudItem.PodServiceLcuuid {
		var podServiceID int
		if cloudItem.PodServiceLcuuid != "" {
			var exists bool
			podServiceItem := p.cache.Tool().PodService().GetByLcuuid(cloudItem.PodServiceLcuuid)
			podServiceID, exists = podServiceItem.Id(), podServiceItem.IsValid()
			if !exists {
				log.Error(resourceAForResourceBNotFound(
					ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN, cloudItem.PodServiceLcuuid,
					ctrlrcommon.RESOURCE_TYPE_POD_EN, cloudItem.Lcuuid,
				), p.metadata.LogPrefixes)
				return nil, nil, false
			}
		}
		mapInfo["pod_service_id"] = podServiceID
		structInfo.PodServiceId.SetNew(podServiceID)
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
	if diffBase.Env != cloudItem.ENV {
		mapInfo["env"] = cloudItem.ENV
		structInfo.Env.Set(diffBase.Env, cloudItem.ENV)
	}
	if diffBase.ContainerIds != cloudItem.ContainerIDs {
		mapInfo["container_ids"] = cloudItem.ContainerIDs
		structInfo.ContainerIds.Set(diffBase.ContainerIds, cloudItem.ContainerIDs)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AzLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AzLcuuid.Set(diffBase.AzLcuuid, cloudItem.AZLcuuid)
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
