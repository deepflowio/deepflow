/*
 * Copyright (c) 2022 Yunshan Networks
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

package resource

import (
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/model"
)

func GetProcesses() ([]model.Process, error) {
	// store vtap info
	var vtaps []mysql.VTap
	if err := mysql.Db.Find(&vtaps).Error; err != nil {
		return nil, err
	}
	type vtapInfo struct {
		Name           string
		Type           int
		LaunchServerID int
	}
	vtapIDToInfo := make(map[int]vtapInfo, len(vtaps))
	for _, vtap := range vtaps {
		vtapIDToInfo[vtap.ID] = vtapInfo{
			Name:           vtap.Name,
			Type:           vtap.Type,
			LaunchServerID: vtap.LaunchServerID,
		}
	}

	// store vm info
	var vms []mysql.VM
	if err := mysql.Db.Find(&vms).Error; err != nil {
		return nil, err
	}
	vmIDToName := make(map[int]string, len(vms))
	for _, vm := range vms {
		vmIDToName[vm.ID] = vm.Name
	}

	// store pod node info
	var podNodes []mysql.PodNode
	if err := mysql.Db.Find(&podNodes).Error; err != nil {
		return nil, err
	}
	podNodeIDToName := make(map[int]string, len(podNodes))
	for _, podNode := range podNodes {
		podNodeIDToName[podNode.ID] = podNode.Name
	}

	// get processes
	var processes []mysql.Process
	if err := mysql.Db.Find(&processes).Error; err != nil {
		return nil, err
	}
	var resp []model.Process
	for _, process := range processes {
		var resourceName string
		deviceType := common.VTAP_TYPE_TO_DEVICE_TYPE[vtapIDToInfo[process.VTapID].Type]
		if deviceType == common.VIF_DEVICE_TYPE_VM {
			resourceName = vmIDToName[vtapIDToInfo[process.VTapID].LaunchServerID]
		} else if deviceType == common.VIF_DEVICE_TYPE_POD_NODE {
			resourceName = podNodeIDToName[vtapIDToInfo[process.VTapID].LaunchServerID]
		}

		processResp := model.Process{
			ResourceType: deviceType,
			ResourceName: resourceName,
			Name:         process.Name,
			VTapName:     vtapIDToInfo[process.VTapID].Name,
			GPID:         process.ID,
			GPName:       process.ProcessName,
			PID:          process.PID,
			ProcessName:  process.ProcessName,
			CommandLine:  process.CommandLine,
			UserName:     process.UserName,
			OSAPPTags:    process.OSAPPTags,
			ResourceID:   vtapIDToInfo[process.VTapID].LaunchServerID,
			StartTime:    process.StartTime.Format(common.GO_BIRTHDAY),
			UpdateAt:     process.UpdatedAt.Format(common.GO_BIRTHDAY),
		}
		resp = append(resp, processResp)
	}

	return resp, nil
}
