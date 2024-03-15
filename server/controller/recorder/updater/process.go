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
	deviceType, deviceID := p.cache.ToolDataSet.GetProcessDeviceTypeAndID(cloudItem.ContainerID, cloudItem.VTapID)
	// add pod node id
	var podNodeID int
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

	// add vm id
	var vmID int
	if deviceType == common.VIF_DEVICE_TYPE_POD ||
		deviceType == common.VIF_DEVICE_TYPE_POD_NODE {
		id, ok := p.cache.ToolDataSet.GetVMIDByPodNodeID(podNodeID)
		if ok {
			vmID = id
		}
	} else {
		vmID = deviceID
	}
	vmInfo, err := p.cache.ToolDataSet.GetVMInfoByID(vmID)
	if err != nil {
		log.Error(err)
	}
	var vpcID int
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
	deviceType, deviceID := p.cache.ToolDataSet.GetProcessDeviceTypeAndID(cloudItem.ContainerID, cloudItem.VTapID)
	if diffBase.DeviceType != deviceType || diffBase.DeviceID != deviceID {
		updateInfo["devicetype"] = deviceType
		updateInfo["deviceid"] = deviceID
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
