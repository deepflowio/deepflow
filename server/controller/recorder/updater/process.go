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
	"github.com/deepflowio/deepflow/server/controller/common"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type Process struct {
	UpdaterBase[cloudmodel.Process, mysql.Process, *diffbase.Process]
}

func NewProcess(wholeCache *cache.Cache, cloudData []cloudmodel.Process) *Process {
	updater := &Process{
		UpdaterBase[cloudmodel.Process, mysql.Process, *diffbase.Process]{
			resourceType: ctrlrcommon.RESOURCE_TYPE_PROCESS_EN,
			cache:        wholeCache,
			dbOperator:   db.NewProcess(),
			diffBaseData: wholeCache.DiffBaseDataSet.Process,
			cloudData:    cloudData,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *Process) getDiffBaseByCloudItem(cloudItem *cloudmodel.Process) (diffBase *diffbase.Process, exits bool) {
	diffBase, exits = p.diffBaseData[cloudItem.Lcuuid]
	return
}

func (p *Process) generateDBItemToAdd(cloudItem *cloudmodel.Process) (*mysql.Process, bool) {
	var deviceType, deviceID, vpcID int
	podID, ok := p.cache.ToolDataSet.GetPodIDByContainerID(cloudItem.ContainerID)
	if len(cloudItem.ContainerID) != 0 && ok {
		deviceType = common.VIF_DEVICE_TYPE_POD
		deviceID = podID
	} else {
		var vtap *mysql.VTap
		if err := mysql.Db.Where("id = ?", cloudItem.VTapID).First(&vtap).Error; err != nil {
			log.Error(err)
		}
		if vtap != nil {
			deviceType = common.VTAP_TYPE_TO_DEVICE_TYPE[vtap.Type]
			deviceID = vtap.LaunchServerID
		}
	}
	var podNodeID, vmID int
	if deviceType == common.VIF_DEVICE_TYPE_POD {
		podInfo, err := p.cache.ToolDataSet.GetPodInfoByID(deviceID)
		if err != nil {
			log.Error(err)
		}

		if podInfo != nil && podInfo.PodNodeID != 0 {
			podNodeID = podInfo.PodNodeID

		}
	} else if deviceType == common.VIF_DEVICE_TYPE_POD_NODE {
		podNodeID = deviceID
	}

	id, ok := p.cache.ToolDataSet.GetVMIDByPodNodeID(podNodeID)
	if ok {
		vmID = id
	}
	vmInfo, err := p.cache.ToolDataSet.GetVMInfoByID(id)
	if err != nil {
		log.Error(err)
	}
	if vmInfo != nil {
		vpcID = vmInfo.VPCID
	}

	dbItem := &mysql.Process{
		Name:        cloudItem.Name,
		VTapID:      cloudItem.VTapID,
		PID:         cloudItem.PID,
		ProcessName: cloudItem.ProcessName,
		CommandLine: cloudItem.CommandLine,
		UserName:    cloudItem.UserName,
		ContainerID: cloudItem.ContainerID,
		OSAPPTags:   cloudItem.OSAPPTags,
		Domain:      p.cache.DomainLcuuid,
		SubDomain:   cloudItem.SubDomainLcuuid,
		NetnsID:     cloudItem.NetnsID,
		DeviceType:  deviceType,
		DeviceID:    deviceID,
		PodNodeID:   podNodeID,
		VMID:        vmID,
		VPCID:       vpcID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid

	return dbItem, true
}

func (p *Process) generateUpdateInfo(diffBase *diffbase.Process, cloudItem *cloudmodel.Process) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.OSAPPTags != cloudItem.OSAPPTags {
		updateInfo["os_app_tags"] = cloudItem.OSAPPTags
	}
	if diffBase.ContainerID != cloudItem.ContainerID {
		updateInfo["container_id"] = cloudItem.ContainerID
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
