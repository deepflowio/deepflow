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

type PodNode struct {
	UpdaterBase[
		cloudmodel.PodNode,
		mysql.PodNode,
		*diffbase.PodNode,
		*message.PodNodeAdd,
		message.PodNodeAdd,
		*message.PodNodeUpdate,
		message.PodNodeUpdate,
		*message.PodNodeFieldsUpdate,
		message.PodNodeFieldsUpdate,
		*message.PodNodeDelete,
		message.PodNodeDelete]
}

func NewPodNode(wholeCache *cache.Cache, cloudData []cloudmodel.PodNode) *PodNode {
	updater := &PodNode{
		newUpdaterBase[
			cloudmodel.PodNode,
			mysql.PodNode,
			*diffbase.PodNode,
			*message.PodNodeAdd,
			message.PodNodeAdd,
			*message.PodNodeUpdate,
			message.PodNodeUpdate,
			*message.PodNodeFieldsUpdate,
			message.PodNodeFieldsUpdate,
			*message.PodNodeDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN,
			wholeCache,
			db.NewPodNode(),
			wholeCache.DiffBaseDataSet.PodNodes,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (n *PodNode) getDiffBaseByCloudItem(cloudItem *cloudmodel.PodNode) (diffBase *diffbase.PodNode, exists bool) {
	diffBase, exists = n.diffBaseData[cloudItem.Lcuuid]
	return
}

func (n *PodNode) generateDBItemToAdd(cloudItem *cloudmodel.PodNode) (*mysql.PodNode, bool) {
	vpcID, exists := n.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	podClusterID, exists := n.cache.ToolDataSet.GetPodClusterIDByLcuuid(cloudItem.PodClusterLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN, cloudItem.PodClusterLcuuid,
			ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	dbItem := &mysql.PodNode{
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
		Domain:       n.cache.DomainLcuuid,
		Region:       cloudItem.RegionLcuuid,
		AZ:           cloudItem.AZLcuuid,
		VPCID:        vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (n *PodNode) generateUpdateInfo(diffBase *diffbase.PodNode, cloudItem *cloudmodel.PodNode) (*message.PodNodeFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.PodNodeFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.Type != cloudItem.Type {
		mapInfo["type"] = cloudItem.Type
		structInfo.Type.Set(diffBase.Type, cloudItem.Type)
	}
	if diffBase.Hostname != cloudItem.Hostname {
		mapInfo["hostname"] = cloudItem.Hostname
		structInfo.Hostname.Set(diffBase.Hostname, cloudItem.Hostname)
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
