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

	"github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type Process struct {
	ManagerComponent
	CUDSubscriberComponent
	deviceType int
	tool       *IPTool
}

func NewProcess(q *queue.OverwriteQueue) *Process {
	mng := &Process{
		newManagerComponent(common.RESOURCE_TYPE_PROCESS_EN, q),
		newCUDSubscriberComponent(common.RESOURCE_TYPE_PROCESS_EN),
		common.PROCESS_INSTANCE_TYPE,
		newTool(),
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (p *Process) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	items := msg.([]*metadbmodel.Process)
	processData, err := p.GetProcessData(md, items)
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
			info, err := md.GetToolDataSet().GetPodInfoByID(podID)
			if err != nil {
				log.Error(err)
			} else {
				podGroupType, ok := md.GetToolDataSet().GetPodGroupTypeByID(info.PodGroupID)
				if !ok {
					log.Errorf("db pod_group type(id: %d) not found", info.PodGroupID, md.LogPrefixORGID)
				}

				opts = append(opts, []eventapi.TagFieldOption{
					eventapi.TagPodID(podID),
					eventapi.TagRegionID(info.RegionID),
					eventapi.TagAZID(info.AZID),
					eventapi.TagVPCID(info.VPCID),
					eventapi.TagPodClusterID(info.PodClusterID),
					eventapi.TagPodGroupID(info.PodGroupID),
					eventapi.TagPodGroupType(metadata.PodGroupTypeMap[podGroupType]),
					eventapi.TagPodNodeID(info.PodNodeID),
					eventapi.TagPodNSID(info.PodNamespaceID),
				}...)
				if l3DeviceOpts, ok := p.tool.getL3DeviceOptionsByPodNodeID(md, info.PodNodeID); ok {
					opts = append(opts, l3DeviceOpts...)
				}
			}

		case common.VIF_DEVICE_TYPE_POD_NODE:
			podNodeID := processData[item.ID].ResourceID
			info, err := md.GetToolDataSet().GetPodNodeInfoByID(podNodeID)
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
				if l3DeviceOpts, ok := p.tool.getL3DeviceOptionsByPodNodeID(md, podNodeID); ok {
					opts = append(opts, l3DeviceOpts...)
				}
			}

		case common.VIF_DEVICE_TYPE_VM:
			vmID := processData[item.ID].ResourceID
			info, err := md.GetToolDataSet().GetVMInfoByID(vmID)
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
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagGProcessID(uint32(item.ID)),
			eventapi.TagGProcessName(item.Name), // TODO @weiqiang why use name
		}...)

		p.createAndEnqueue(
			md,
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			p.deviceType,
			item.ID,
			opts...,
		)
	}
}

func (p *Process) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.Process) {
		opts := []eventapi.TagFieldOption{
			eventapi.TagGProcessID(uint32(item.ID)),
			eventapi.TagGProcessName(item.Name),
		}
		p.createAndEnqueue(md, item.Lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, item.Name, p.deviceType, item.ID, opts...)
	}
}

type ProcessData struct {
	ResourceType int
	ResourceName string
	ResourceID   int
	VTapName     string
}

func (p *Process) GetProcessData(md *message.Metadata, processes []*metadbmodel.Process) (map[int]ProcessData, error) {
	// store vtap info
	vtapIDs := mapset.NewSet[uint32]()
	for _, item := range processes {
		vtapIDs.Add(item.VTapID)
	}
	var vtaps []metadbmodel.VTap
	if err := md.GetDB().Where("id IN (?)", vtapIDs.ToSlice()).Find(&vtaps).Error; err != nil {
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
	var vms []metadbmodel.VM
	if err := md.GetDB().Where("id IN (?)", vmLaunchServerIDs.ToSlice()).Find(&vms).Error; err != nil {
		return nil, err
	}
	vmIDToName := make(map[int]string, len(vms))
	for _, vm := range vms {
		vmIDToName[vm.ID] = vm.Name
	}

	// store pod node info
	var podNodes []metadbmodel.PodNode
	if err := md.GetDB().Where("id IN (?)", podNodeLaunchServerIDs.ToSlice()).Find(&podNodes).Error; err != nil {
		return nil, err
	}
	podNodeIDToName := make(map[int]string, len(podNodes))
	for _, podNode := range podNodes {
		podNodeIDToName[podNode.ID] = podNode.Name
	}

	// store pod info
	var pods []metadbmodel.Pod
	if err := md.GetDB().Find(&pods).Error; err != nil {
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
