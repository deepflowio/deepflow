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
)

type VM struct {
	UpdaterBase[cloudmodel.VM, mysql.VM, *diffbase.VM]
}

func NewVM(wholeCache *cache.Cache, cloudData []cloudmodel.VM) *VM {
	updater := &VM{
		UpdaterBase[cloudmodel.VM, mysql.VM, *diffbase.VM]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_VM_EN,
			cache:        wholeCache,
			dbOperator:   db.NewVM(),
			diffBaseData: wholeCache.DiffBaseDataSet.VMs,
			cloudData:    cloudData,
		},
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

func (m *VM) generateUpdateInfo(diffBase *diffbase.VM, cloudItem *cloudmodel.VM) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := m.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.Lcuuid,
			))
			return nil, false
		}
		updateInfo["epc_id"] = vpcID
	}
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.Label != cloudItem.Label {
		updateInfo["label"] = cloudItem.Label
	}
	if diffBase.State != cloudItem.State {
		updateInfo["state"] = cloudItem.State
	}
	if diffBase.HType != cloudItem.HType {
		updateInfo["htype"] = cloudItem.HType
	}
	if diffBase.LaunchServer != cloudItem.LaunchServer {
		updateInfo["launch_server"] = cloudItem.LaunchServer
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		updateInfo["az"] = cloudItem.AZLcuuid
	}
	if cloudcommon.DiffMap(diffBase.CloudTags, cloudItem.CloudTags) {
		tagsJson, _ := json.Marshal(cloudItem.CloudTags)
		updateInfo["cloud_tags"] = tagsJson
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return updateInfo, false
}
