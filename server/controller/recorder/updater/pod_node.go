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
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
)

// PodNodeMessageFactory defines the message factory for PodNode
type PodNodeMessageFactory struct{}

func (f *PodNodeMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedPodNodes{}
}

func (f *PodNodeMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedPodNode{}
}

func (f *PodNodeMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedPodNodes{}
}

func (f *PodNodeMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedPodNodeFields{}
}

type PodNode struct {
	UpdaterBase[
		cloudmodel.PodNode,
		*diffbase.PodNode,
		*metadbmodel.PodNode,
		metadbmodel.PodNode,
	]
}

func NewPodNode(wholeCache *cache.Cache, cloudData []cloudmodel.PodNode) *PodNode {
	if !hasMessageFactory(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN) {
		RegisterMessageFactory(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, &PodNodeMessageFactory{})
	}

	updater := &PodNode{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN,
			wholeCache,
			db.NewPodNode().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.PodNodes,
			cloudData,
		),
	}
	updater.setDataGenerator(updater)
	return updater
}

// 实现 DataGenerator 接口

func (p *PodNode) generateDBItemToAdd(cloudItem *cloudmodel.PodNode) (*metadbmodel.PodNode, bool) {
	vpcID, exists := p.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	podClusterID, exists := p.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, cloudItem.Lcuuid,
		), p.metadata.LogPrefixes)
		return nil, false
	}
	dbItem := &metadbmodel.PodNode{
		Name:         cloudItem.Name,
		Type:         cloudItem.Type,
		MemTotal:     cloudItem.MemTotal,
		VCPUNum:      cloudItem.VCPUNum,
		ServerType:   cloudItem.ServerType,
		State:        cloudItem.State,
		IP:           cloudItem.IP,
		Hostname:     cloudItem.Hostname,
		PodClusterID: podClusterID,
		SubDomain:    cloudItem.SubDomainLcuuid,
		Domain:       p.metadata.GetDomainLcuuid(),
		Region:       cloudItem.RegionLcuuid,
		AZ:           cloudItem.AZLcuuid,
		VPCID:        vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (p *PodNode) generateUpdateInfo(diffBase *diffbase.PodNode, cloudItem *cloudmodel.PodNode) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := &message.UpdatedPodNodeFields{}
	mapInfo := make(map[string]interface{})
	if diffBase.Type != cloudItem.Type {
		mapInfo["type"] = cloudItem.Type
		structInfo.Type.Set(diffBase.Type, cloudItem.Type)
	}
	if diffBase.Hostname != cloudItem.Hostname {
		mapInfo["hostname"] = cloudItem.Hostname
		structInfo.Hostname.Set(diffBase.Hostname, cloudItem.Hostname)
	}
	if diffBase.IP != cloudItem.IP {
		mapInfo["ip"] = cloudItem.IP
		structInfo.IP.Set(diffBase.IP, cloudItem.IP)
	}
	if diffBase.State != cloudItem.State {
		mapInfo["state"] = cloudItem.State
		structInfo.State.Set(diffBase.State, cloudItem.State)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	}
	if diffBase.VCPUNum != cloudItem.VCPUNum {
		mapInfo["vcpu_num"] = cloudItem.VCPUNum
		structInfo.VCPUNum.Set(diffBase.VCPUNum, cloudItem.VCPUNum)
	}
	if diffBase.MemTotal != cloudItem.MemTotal {
		mapInfo["mem_total"] = cloudItem.MemTotal
		structInfo.MemTotal.Set(diffBase.MemTotal, cloudItem.MemTotal)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
