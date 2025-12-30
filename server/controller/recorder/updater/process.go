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
	mapset "github.com/deckarep/golang-set/v2"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/db/idmng"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type Process struct {
	UpdaterBase[
		cloudmodel.Process,
		*diffbase.Process,
		*metadbmodel.Process,
		metadbmodel.Process,
		*message.AddedProcesses,
		message.AddedProcesses,
		message.ProcessAddAddition,
		*message.UpdatedProcess,
		message.UpdatedProcess,
		*message.UpdatedProcessFields,
		message.UpdatedProcessFields,
		*message.DeletedProcesses,
		message.DeletedProcesses,
		message.ProcessDeleteAddition]
}

func NewProcess(wholeCache *cache.Cache, cloudData []cloudmodel.Process) *Process {
	updater := &Process{
		newUpdaterBase[
			cloudmodel.Process,
			*diffbase.Process,
			*metadbmodel.Process,
			metadbmodel.Process,
			*message.AddedProcesses,
			message.AddedProcesses,
			message.ProcessAddAddition,
			*message.UpdatedProcess,
			message.UpdatedProcess,
			*message.UpdatedProcessFields,
			message.UpdatedProcessFields,
			*message.DeletedProcesses,
			message.DeletedProcesses,
			message.ProcessDeleteAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_PROCESS_EN,
			wholeCache,
			db.NewProcess().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.Process,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	updater.hookers[hookerBeforeDBAddPage] = updater
	updater.hookers[hookerAfterDBDeletePage] = updater
	return updater
}

func (p *Process) generateDBItemToAdd(cloudItem *cloudmodel.Process) (*metadbmodel.Process, bool) {
	deviceType, deviceID := p.cache.ToolDataSet.GetProcessDeviceTypeAndID(cloudItem.ContainerID, cloudItem.VTapID)
	// add pod node id
	var podNodeID int
	var podGroupID int
	if deviceType == common.VIF_DEVICE_TYPE_POD {
		podInfo, err := p.cache.ToolDataSet.GetPodInfoByID(deviceID)
		if err != nil {
			log.Error(err)
		}

		if podInfo != nil {
			podNodeID = podInfo.PodNodeID
			podGroupID = podInfo.PodGroupID
		}
	} else if deviceType == common.VIF_DEVICE_TYPE_POD_NODE {
		podNodeID = deviceID
	}

	// add vm id
	var vmID int
	if deviceType == common.VIF_DEVICE_TYPE_POD ||
		deviceType == common.VIF_DEVICE_TYPE_POD_NODE {
		if podNodeID != 0 {
			id, ok := p.cache.ToolDataSet.GetVMIDByPodNodeID(podNodeID)
			if ok {
				vmID = id
			}

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
	dbItem := &metadbmodel.Process{
		Name:        cloudItem.Name,
		VTapID:      cloudItem.VTapID,
		PID:         cloudItem.PID,
		ProcessName: cloudItem.ProcessName,
		CommandLine: cloudItem.CommandLine,
		StartTime:   cloudItem.StartTime,
		UserName:    cloudItem.UserName,
		ContainerID: cloudItem.ContainerID,
		OSAPPTags:   cloudItem.OSAPPTags,
		Domain:      p.metadata.GetDomainLcuuid(),
		SubDomain:   cloudItem.SubDomainLcuuid,
		NetnsID:     cloudItem.NetnsID,
		DeviceType:  deviceType,
		DeviceID:    deviceID,
		PodGroupID:  podGroupID,
		PodNodeID:   podNodeID,
		VMID:        vmID,
		VPCID:       vpcID,
	}

	gid, _ := p.cache.ToolDataSet.GetProcessGIDByIdentifier(
		p.cache.ToolDataSet.GetProcessIdentifierByDBProcess(dbItem),
	)
	dbItem.GID = gid
	dbItem.Lcuuid = cloudItem.Lcuuid

	return dbItem, true
}

func (p *Process) generateUpdateInfo(diffBase *diffbase.Process, cloudItem *cloudmodel.Process) (*message.UpdatedProcessFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedProcessFields)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.OSAPPTags != cloudItem.OSAPPTags {
		mapInfo["os_app_tags"] = cloudItem.OSAPPTags
		structInfo.OSAPPTags.Set(diffBase.OSAPPTags, cloudItem.OSAPPTags)
	}
	if diffBase.ContainerID != cloudItem.ContainerID {
		mapInfo["container_id"] = cloudItem.ContainerID
		structInfo.ContainerID.Set(diffBase.ContainerID, cloudItem.ContainerID)
	}
	deviceType, deviceID := p.cache.ToolDataSet.GetProcessDeviceTypeAndID(cloudItem.ContainerID, cloudItem.VTapID)
	if diffBase.DeviceType != deviceType || diffBase.DeviceID != deviceID {
		mapInfo["devicetype"] = deviceType
		mapInfo["deviceid"] = deviceID
	}

	if len(mapInfo) > 0 {
		var podGroupID int
		if deviceType == common.VIF_DEVICE_TYPE_POD {
			podInfo, err := p.cache.ToolDataSet.GetPodInfoByID(deviceID)
			if err != nil {
				log.Error(err)
				return nil, nil, false
			}

			if podInfo != nil {
				podGroupID = podInfo.PodGroupID
			}
		}
		gid, ok := p.cache.ToolDataSet.GetProcessGIDByIdentifier(
			p.cache.ToolDataSet.GetProcessIdentifier(diffBase.Name, cloudItem.ProcessName, podGroupID, cloudItem.VTapID, cloudItem.CommandLine),
		)
		if !ok {
			log.Errorf("process %s gid not found", diffBase.Lcuuid, p.metadata.LogPrefixes)
			return nil, nil, false
		}
		structInfo.GID.Set(gid, gid)
	}
	return structInfo, mapInfo, len(mapInfo) > 0
}

func (p *Process) beforeAddPage(dbData []*metadbmodel.Process) ([]*metadbmodel.Process, *message.ProcessAddAddition, bool) {
	identifierToNewGID := make(map[tool.ProcessIdentifier]uint32)
	for _, item := range dbData {
		if item.GID != 0 {
			continue
		}
		identifier := p.cache.ToolDataSet.GetProcessIdentifierByDBProcess(item)
		if _, ok := identifierToNewGID[identifier]; !ok {
			identifierToNewGID[identifier] = item.GID
		}
	}
	var createdGIDs []uint32
	if len(identifierToNewGID) > 0 {
		// TODO combine with operator module
		// TODO support partial ids allocation
		gidResourceType := ctrlrcommon.RESOURCE_TYPE_GPROCESS_EN
		ids, err := idmng.GetIDs(p.metadata.GetORGID(), gidResourceType, len(identifierToNewGID))
		if err != nil {
			log.Errorf("%s request gids failed", gidResourceType, p.metadata.LogPrefixes)
			return dbData, nil, false
		}
		log.Infof("%s use gids: %v, expected count: %d, true count: %d", gidResourceType, ids, len(identifierToNewGID), len(ids), p.metadata.LogPrefixes)

		start := 0
		for k := range identifierToNewGID {
			if start >= len(ids) {
				log.Errorf("process identifier %s out of range, max is %d", k, len(ids)-1, p.metadata.LogPrefixes)
				break
			}
			identifierToNewGID[k] = uint32(ids[start])
			createdGIDs = append(createdGIDs, identifierToNewGID[k])
			start++
		}

		for _, item := range dbData {
			if item.GID != 0 {
				continue
			}
			item.GID = identifierToNewGID[p.cache.ToolDataSet.GetProcessIdentifierByDBProcess(item)]
		}
	}
	return dbData, &message.ProcessAddAddition{}, true
}

func (p *Process) afterDeletePage(dbData []*metadbmodel.Process) (*message.ProcessDeleteAddition, bool) {
	deletedGIDs := mapset.NewSet[uint32]()
	for _, item := range dbData {
		if gid, ok := p.cache.ToolDataSet.GetProcessGIDByIdentifier(p.cache.ToolDataSet.GetProcessIdentifierByDBProcess(item)); ok {
			if p.cache.ToolDataSet.IsProcessGIDSoftDeleted(gid) {
				deletedGIDs.Add(gid)
			}
		}
	}
	return &message.ProcessDeleteAddition{DeletedGIDs: deletedGIDs.ToSlice()}, true
}
