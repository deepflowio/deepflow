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
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message/types"
)

type ProcessMessageFactory struct{}

func (f *ProcessMessageFactory) CreateAddedMessage() types.Added {
	return &message.AddedProcesses{}
}

func (f *ProcessMessageFactory) CreateUpdatedMessage() types.Updated {
	return &message.UpdatedProcess{}
}

func (f *ProcessMessageFactory) CreateDeletedMessage() types.Deleted {
	return &message.DeletedProcesses{}
}

func (f *ProcessMessageFactory) CreateUpdatedFields() types.UpdatedFields {
	return &message.UpdatedProcessFields{}
}

type Process struct {
	UpdaterBase[cloudmodel.Process, *diffbase.Process, *metadbmodel.Process, metadbmodel.Process]
}

func NewProcess(wholeCache *cache.Cache, cloudData []cloudmodel.Process) *Process {
	updater := &Process{
		UpdaterBase: newUpdaterBase(
			ctrlrcommon.RESOURCE_TYPE_PROCESS_EN,
			wholeCache,
			db.NewProcess().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBases().Process().GetAll(),
			cloudData,
		),
	}
	updater.setDataGenerator(updater)

	if !hasMessageFactory(updater.resourceType) {
		RegisterMessageFactory(updater.resourceType, &ProcessMessageFactory{})
	}

	updater.hookers[hookerBeforeDBAddPage] = updater
	updater.hookers[hookerAfterDBDeletePage] = updater
	return updater
}

func (p *Process) generateDBItemToAdd(cloudItem *cloudmodel.Process) (*metadbmodel.Process, bool) {
	deviceType, deviceID := p.cache.Tool().GetProcessDeviceTypeAndID(cloudItem.ContainerID, int(cloudItem.VTapID))
	// add pod node id
	var podNodeID int
	var podGroupID int
	if deviceType == common.VIF_DEVICE_TYPE_POD {
		podItem := p.cache.Tool().Pod().GetById(deviceID)
		if podItem.IsValid() {
			podNodeID = podItem.PodNodeId()
			podGroupID = podItem.PodGroupId()
		}
	} else if deviceType == common.VIF_DEVICE_TYPE_POD_NODE {
		podNodeID = deviceID
	}

	// add vm id
	var vmID int
	if deviceType == common.VIF_DEVICE_TYPE_POD ||
		deviceType == common.VIF_DEVICE_TYPE_POD_NODE {
		if podNodeID != 0 {
			vmID = p.cache.Tool().PodNode().GetById(podNodeID).VmId()
		}
	} else {
		vmID = deviceID
	}
	var vpcID int
	vmItem := p.cache.Tool().Vm().GetById(vmID)
	if vmItem.IsValid() {
		vpcID = vmItem.VpcId()
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

	gid, _ := p.cache.Tool().Process().GetGIDByIdentifier(
		p.cache.Tool().Process().GenerateIdentifierByDBProcess(dbItem),
	)
	dbItem.GID = gid
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (p *Process) generateUpdateInfo(diffBase *diffbase.Process, cloudItem *cloudmodel.Process) (types.UpdatedFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedProcessFields)
	mapInfo := make(map[string]interface{})
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.OsAppTags != cloudItem.OSAPPTags {
		mapInfo["os_app_tags"] = cloudItem.OSAPPTags
		structInfo.OsAppTags.Set(diffBase.OsAppTags, cloudItem.OSAPPTags)
	}
	if diffBase.ContainerId != cloudItem.ContainerID {
		mapInfo["container_id"] = cloudItem.ContainerID
		structInfo.ContainerId.Set(diffBase.ContainerId, cloudItem.ContainerID)
	}
	deviceType, deviceID := p.cache.Tool().GetProcessDeviceTypeAndID(cloudItem.ContainerID, int(cloudItem.VTapID))
	if diffBase.DeviceType != deviceType || diffBase.DeviceId != deviceID {
		mapInfo["devicetype"] = deviceType
		mapInfo["deviceid"] = deviceID
	}

	if len(mapInfo) > 0 {
		var podGroupID int
		if deviceType == common.VIF_DEVICE_TYPE_POD {
			podItem := p.cache.Tool().Pod().GetById(deviceID)
			if !podItem.IsValid() {
				return nil, nil, false
			}
			podGroupID = podItem.PodGroupId()
		}
		gid, ok := p.cache.Tool().Process().GetGIDByIdentifier(
			p.cache.Tool().Process().GenerateIdentifier(diffBase.Name, cloudItem.ProcessName, podGroupID, cloudItem.VTapID, cloudItem.CommandLine),
		)
		if !ok {
			log.Errorf("process %s gid not found", diffBase.Lcuuid, p.metadata.LogPrefixes)
			return nil, nil, false
		}
		structInfo.Gid.Set(gid, gid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}

func (p *Process) beforeAddPage(dbData []*metadbmodel.Process) ([]*metadbmodel.Process, interface{}, bool) {
	identifierToNewGID := make(map[tool.ProcessIdentifier]uint32)
	for _, item := range dbData {
		if item.GID != 0 {
			continue
		}
		identifier := p.cache.Tool().Process().GenerateIdentifierByDBProcess(item)
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
			item.GID = identifierToNewGID[p.cache.Tool().Process().GenerateIdentifierByDBProcess(item)]
		}
	}
	return dbData, &message.ProcessAddAddition{}, true
}

func (p *Process) afterDeletePage(dbData []*metadbmodel.Process) (interface{}, bool) {
	deletedGIDs := mapset.NewSet[uint32]()
	for _, item := range dbData {
		if gid, ok := p.cache.Tool().Process().GetGIDByIdentifier(p.cache.Tool().Process().GenerateIdentifierByDBProcess(item)); ok {
			if p.cache.Tool().Process().IsProcessGIDSoftDeleted(gid) {
				deletedGIDs.Add(gid)
			}
		}
	}
	return &message.ProcessDeleteAddition{DeletedGIDs: deletedGIDs.ToSlice()}, true
}
