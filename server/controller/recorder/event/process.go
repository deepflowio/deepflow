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

package event

import (
	"fmt"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"golang.org/x/exp/slices"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type Process struct {
	EventManagerBase
	deviceType int
	tool       *IPTool
}

func NewProcess(toolDS *tool.DataSet, eq *queue.OverwriteQueue) *Process {
	mng := &Process{
		newEventManagerBase("process",
			toolDS,
			eq,
		),
		common.PROCESS_INSTANCE_TYPE,
		newTool(toolDS),
	}
	return mng
}

func (p *Process) ProduceByAdd(items []*mysql.Process) {
	processData, err := p.GetProcessData(items)
	if err != nil {
		log.Error(err)
	}
	for _, item := range items {
		description := fmt.Sprintf("agent %s report process %s cmdline %s",
			processData[item.ID].VTapName, item.ProcessName, item.CommandLine)
		opts := []eventapi.TagFieldOption{eventapi.TagDescription(description)}

		switch t := processData[item.ID].ResourceType; t {
		case common.VIF_DEVICE_TYPE_POD:
			podID := processData[item.ID].ResourceID
			info, err := p.ToolDataSet.GetPodInfoByID(podID)
			if err != nil {
				log.Error(err)
			} else {
				opts = append(opts, []eventapi.TagFieldOption{
					eventapi.TagPodID(podID),
					eventapi.TagRegionID(info.RegionID),
					eventapi.TagAZID(info.AZID),
					eventapi.TagVPCID(info.VPCID),
					eventapi.TagPodClusterID(info.PodClusterID),
					eventapi.TagPodGroupID(info.PodGroupID),
					eventapi.TagPodNodeID(info.PodNodeID),
					eventapi.TagPodNSID(info.PodNamespaceID),
				}...)
				if l3DeviceOpts, ok := p.tool.getL3DeviceOptionsByPodNodeID(info.PodNodeID); ok {
					opts = append(opts, l3DeviceOpts...)
				}
			}

		case common.VIF_DEVICE_TYPE_POD_NODE:
			podNodeID := processData[item.ID].ResourceID
			info, err := p.ToolDataSet.GetPodNodeInfoByID(podNodeID)
			if err != nil {
				log.Error(err)
			} else {
				opts = append(opts, []eventapi.TagFieldOption{
					eventapi.TagPodNodeID(podNodeID),
					eventapi.TagRegionID(info.RegionID),
					eventapi.TagAZID(info.AZID),
					eventapi.TagVPCID(info.VPCID),
					eventapi.TagPodClusterID(info.PodClusterID),
				}...)
				if l3DeviceOpts, ok := p.tool.getL3DeviceOptionsByPodNodeID(podNodeID); ok {
					opts = append(opts, l3DeviceOpts...)
				}
			}

		case common.VIF_DEVICE_TYPE_VM:
			vmID := processData[item.ID].ResourceID
			info, err := p.ToolDataSet.GetVMInfoByID(vmID)
			if err != nil {
				log.Error(err)
			} else {
				opts = append(opts, []eventapi.TagFieldOption{
					eventapi.TagL3DeviceType(processData[item.ID].ResourceType),
					eventapi.TagL3DeviceID(vmID),
					eventapi.TagAZID(info.AZID),
					eventapi.TagRegionID(info.RegionID),
					eventapi.TagHostID(info.HostID),
					eventapi.TagVPCID(info.VPCID),
				}...)
			}
		default:
			log.Error("cannot support type: %s", t)
		}

		p.createProcessAndEnqueue(
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			p.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (p *Process) ProduceByUpdate(cloudItem *cloudmodel.Process, diffBase *diffbase.Process) {
}

func (p *Process) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		processInfo, exists := p.ToolDataSet.GetProcessInfoByLcuuid(lcuuid)
		if !exists {
			log.Error(p.org.LogPre("process info not fount, lcuuid: %s", lcuuid))
		} else {
			id = processInfo.ID
			name = processInfo.Name
		}

		p.createProcessAndEnqueue(
			lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_DELETE,
			name,
			p.deviceType,
			id,
		)
	}
}

type ProcessData struct {
	ResourceType int
	ResourceName string
	ResourceID   int
	VTapName     string
}

func (p *Process) GetProcessData(processes []*mysql.Process) (map[int]ProcessData, error) {
	// store vtap info
	vtapIDs := mapset.NewSet[uint32]()
	for _, item := range processes {
		vtapIDs.Add(item.VTapID)
	}
	var vtaps []mysql.VTap
	if err := p.org.DB.Where("id IN (?)", vtapIDs.ToSlice()).Find(&vtaps).Error; err != nil {
		return nil, err
	}
	type vtapInfo struct {
		Name           string
		Type           int
		LaunchServerID int
	}
	vtapIDToInfo := make(map[int]vtapInfo, len(vtaps))
	vmLaunchServerIDs := mapset.NewSet[int]()
	podNodeLaunchServerIDs := mapset.NewSet[int]()
	for _, vtap := range vtaps {
		vtapIDToInfo[vtap.ID] = vtapInfo{
			Name:           vtap.Name,
			Type:           vtap.Type,
			LaunchServerID: vtap.LaunchServerID,
		}
		if slices.Contains([]int{common.VTAP_TYPE_WORKLOAD_V, common.VTAP_TYPE_WORKLOAD_P}, vtap.Type) {
			vmLaunchServerIDs.Add(vtap.LaunchServerID)
		} else if slices.Contains([]int{common.VTAP_TYPE_POD_HOST, common.VTAP_TYPE_POD_VM}, vtap.Type) {
			podNodeLaunchServerIDs.Add(vtap.LaunchServerID)
		}
	}

	// store vm info
	var vms []mysql.VM
	if err := p.org.DB.Where("id IN (?)", vmLaunchServerIDs.ToSlice()).Find(&vms).Error; err != nil {
		return nil, err
	}
	vmIDToName := make(map[int]string, len(vms))
	for _, vm := range vms {
		vmIDToName[vm.ID] = vm.Name
	}

	// store pod node info
	var podNodes []mysql.PodNode
	if err := p.org.DB.Where("id IN (?)", podNodeLaunchServerIDs.ToSlice()).Find(&podNodes).Error; err != nil {
		return nil, err
	}
	podNodeIDToName := make(map[int]string, len(podNodes))
	for _, podNode := range podNodes {
		podNodeIDToName[podNode.ID] = podNode.Name
	}

	// store pod info
	var pods []mysql.Pod
	if err := p.org.DB.Find(&pods).Error; err != nil {
		return nil, err
	}
	podIDToName := make(map[int]string, len(pods))
	containerIDToPodID := make(map[string]int)
	for _, pod := range pods {
		podIDToName[pod.ID] = pod.Name
		var containerIDs []string
		if len(pod.ContainerIDs) > 0 {
			containerIDs = strings.Split(pod.ContainerIDs, ", ")
		}
		for _, id := range containerIDs {
			containerIDToPodID[id] = pod.ID
		}
	}

	resp := make(map[int]ProcessData, len(processes))
	for _, process := range processes {
		var deviceType, resourceID int
		var resourceName string

		pVTapID := int(process.VTapID)
		if podID, ok := containerIDToPodID[process.ContainerID]; ok {
			deviceType = common.VIF_DEVICE_TYPE_POD
			resourceName = podIDToName[podID]
			resourceID = podID
		} else {
			deviceType = common.VTAP_TYPE_TO_DEVICE_TYPE[vtapIDToInfo[pVTapID].Type]
			if deviceType == common.VIF_DEVICE_TYPE_VM {
				resourceName = vmIDToName[vtapIDToInfo[pVTapID].LaunchServerID]
			} else if deviceType == common.VIF_DEVICE_TYPE_POD_NODE {
				resourceName = podNodeIDToName[vtapIDToInfo[pVTapID].LaunchServerID]
			}
			resourceID = vtapIDToInfo[pVTapID].LaunchServerID
		}
		resp[process.ID] = ProcessData{
			ResourceType: deviceType,
			ResourceID:   resourceID,
			ResourceName: resourceName,
			VTapName:     vtapIDToInfo[pVTapID].Name,
		}
	}
	return resp, nil
}
