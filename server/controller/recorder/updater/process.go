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
		*message.ProcessAdd,
		message.ProcessAdd,
		message.ProcessAddAddition,
		*message.ProcessUpdate,
		message.ProcessUpdate,
		*message.ProcessFieldsUpdate,
		message.ProcessFieldsUpdate,
		*message.ProcessDelete,
		message.ProcessDelete,
		message.ProcessDeleteAddition]
}

func NewProcess(wholeCache *cache.Cache, cloudData []cloudmodel.Process) *Process {
	updater := &Process{
		newUpdaterBase[
			cloudmodel.Process,
			*diffbase.Process,
			*metadbmodel.Process,
			metadbmodel.Process,
			*message.ProcessAdd,
			message.ProcessAdd,
			message.ProcessAddAddition,
			*message.ProcessUpdate,
			message.ProcessUpdate,
			*message.ProcessFieldsUpdate,
			message.ProcessFieldsUpdate,
			*message.ProcessDelete,
			message.ProcessDelete,
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

func (p *Process) getDiffBaseByCloudItem(cloudItem *cloudmodel.Process) (diffBase *diffbase.Process, exits bool) {
	diffBase, exits = p.diffBaseData[cloudItem.Lcuuid]
	return
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
		UserName:    cloudItem.UserName,
		ContainerID: cloudItem.ContainerID,
		OSAPPTags:   cloudItem.OSAPPTags,
		Domain:      p.metadata.Domain.Lcuuid,
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
		p.cache.ToolDataSet.GetProcessIdentifierByProcess(dbItem),
	)
	dbItem.GID = gid
	dbItem.Lcuuid = cloudItem.Lcuuid

	return dbItem, true
}

func (p *Process) generateUpdateInfo(diffBase *diffbase.Process, cloudItem *cloudmodel.Process) (*message.ProcessFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.ProcessFieldsUpdate)
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

	return structInfo, mapInfo, len(mapInfo) > 0
}

func (p *Process) beforeAddPage(dbData []*metadbmodel.Process) ([]*metadbmodel.Process, *message.ProcessAddAddition, bool) {
	idToNewGIDFlag := make(map[int]bool)
	identifierToNewGID := make(map[tool.ProcessIdentifier]uint64)
	for _, item := range dbData {
		if item.GID != 0 {
			continue
		}
		identifier := p.cache.ToolDataSet.GetProcessIdentifierByProcess(item)
		if _, ok := identifierToNewGID[identifier]; !ok {
			idToNewGIDFlag[item.ID] = true
			identifierToNewGID[identifier] = item.GID
		}
	}
	log.Infof("TODO beforeAddPage idToNewGIDFlag: %#v", idToNewGIDFlag, p.metadata.LogPrefixes)
	log.Infof("TODO beforeAddPage identifierToNewGID: %#v", identifierToNewGID, p.metadata.LogPrefixes)
	if len(identifierToNewGID) > 0 {
		// TODO combine with operator module
		// TODO support partial ids allocation
		gidResourceType := ctrlrcommon.RESOURCE_TYPE_GPROCESS_EN
		ids, err := idmng.GetIDs(p.metadata.GetORGID(), gidResourceType, len(identifierToNewGID))
		if err != nil {
			log.Errorf("%s request gids failed", gidResourceType, p.metadata.LogPrefixes)
			return dbData, nil, false
		}
		log.Infof("%s use gids: %v", gidResourceType, ids, p.metadata.LogPrefixes)

		start := 0
		for k := range identifierToNewGID {
			identifierToNewGID[k] = uint64(ids[start])
			start++
		}

		for _, item := range dbData {
			if item.GID != 0 {
				continue
			}
			item.GID = identifierToNewGID[p.cache.ToolDataSet.GetProcessIdentifierByProcess(item)]
		}
	}
	return dbData, &message.ProcessAddAddition{IDToTagRecorderNewGIDFlag: idToNewGIDFlag}, true
}

func (p *Process) afterDeletePage(dbData []*metadbmodel.Process) (*message.ProcessDeleteAddition, bool) {
	deletedGIDs := mapset.NewSet[uint64]()
	gids := make([]int, 0)
	for _, item := range dbData {
		if _, ok := p.cache.ToolDataSet.GetProcessGIDByIdentifier(p.cache.ToolDataSet.GetProcessIdentifierByProcess(item)); ok {
			deletedGIDs.Add(item.GID)
			gids = append(gids, int(item.GID))
		}
	}
	if deletedGIDs.Cardinality() == 0 {
		return &message.ProcessDeleteAddition{}, false
	}

	gidResourceType := ctrlrcommon.RESOURCE_TYPE_GPROCESS_EN
	err := idmng.ReleaseIDs(p.metadata.GetORGID(), gidResourceType, gids)
	if err != nil {
		log.Errorf("%s release gids: %v failed", gidResourceType, gids, p.metadata.LogPrefixes)
	}
	log.Infof("%s return used gids: %v", gidResourceType, gids, p.metadata.LogPrefixes)
	return &message.ProcessDeleteAddition{DeletedGIDs: deletedGIDs.ToSlice()}, true
}
