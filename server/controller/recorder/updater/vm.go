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
	"encoding/json"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type VM struct {
	UpdaterBase[
		cloudmodel.VM,
		mysql.VM,
		*diffbase.VM,
		*message.VMAdd,
		message.VMAdd,
		*message.VMUpdate,
		message.VMUpdate,
		*message.VMFieldsUpdate,
		message.VMFieldsUpdate,
		*message.VMDelete,
		message.VMDelete]
}

func NewVM(wholeCache *cache.Cache, cloudData []cloudmodel.VM) *VM {
	updater := &VM{
		newUpdaterBase[
			cloudmodel.VM,
			mysql.VM,
			*diffbase.VM,
			*message.VMAdd,
			message.VMAdd,
			*message.VMUpdate,
			message.VMUpdate,
			*message.VMFieldsUpdate,
			message.VMFieldsUpdate,
			*message.VMDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_VM_EN,
			wholeCache,
			db.NewVM(),
			wholeCache.DiffBaseDataSet.VMs,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (m *VM) getDiffBaseByCloudItem(cloudItem *cloudmodel.VM) (diffBase *diffbase.VM, exists bool) {
	diffBase, exists = m.diffBaseData[cloudItem.Lcuuid]
	return
}

func (m *VM) generateDBItemToAdd(cloudItem *cloudmodel.VM) (*mysql.VM, bool) {
	vpcID, exists := m.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Errorf(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.Lcuuid,
		))
		return nil, false
	}
	cloudTags := map[string]string{}
	if cloudItem.CloudTags != nil {
		cloudTags = cloudItem.CloudTags
	}
	dbItem := &mysql.VM{
		Name:         cloudItem.Name,
		Label:        cloudItem.Label,
		UID:          cloudItem.Label,
		State:        cloudItem.State,
		HType:        cloudItem.HType,
		LaunchServer: cloudItem.LaunchServer,
		Domain:       m.cache.DomainLcuuid,
		Region:       cloudItem.RegionLcuuid,
		AZ:           cloudItem.AZLcuuid,
		VPCID:        vpcID,
		CloudTags:    cloudTags,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	if !cloudItem.CreatedAt.IsZero() {
		dbItem.CreatedAt = cloudItem.CreatedAt
	}
	return dbItem, true
}

func (m *VM) generateUpdateInfo(diffBase *diffbase.VM, cloudItem *cloudmodel.VM) (*message.VMFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.VMFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := m.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.Lcuuid,
			))
			return nil, nil, false
		}
		mapInfo["epc_id"] = vpcID
		structInfo.VPCID.SetNew(vpcID) // TODO is old value needed?
		structInfo.VPCLcuuid.Set(diffBase.VPCLcuuid, cloudItem.VPCLcuuid)
	}
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}
	if diffBase.State != cloudItem.State {
		mapInfo["state"] = cloudItem.State
		structInfo.State.Set(diffBase.State, cloudItem.State)
	}
	if diffBase.HType != cloudItem.HType {
		mapInfo["htype"] = cloudItem.HType
		structInfo.HType.Set(diffBase.HType, cloudItem.HType)
	}
	if diffBase.LaunchServer != cloudItem.LaunchServer {
		mapInfo["launch_server"] = cloudItem.LaunchServer
		structInfo.LaunchServer.Set(diffBase.LaunchServer, cloudItem.LaunchServer)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	}
	if cloudcommon.DiffMap(diffBase.CloudTags, cloudItem.CloudTags) {
		tagsJson, _ := json.Marshal(cloudItem.CloudTags)
		mapInfo["cloud_tags"] = tagsJson
		structInfo.CloudTags.Set(diffBase.CloudTags, cloudItem.CloudTags)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
