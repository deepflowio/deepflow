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
	"encoding/json"
	"time"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/recorder/statsd"
)

type VM struct {
	UpdaterBase[
		cloudmodel.VM,
		*diffbase.VM,
		*metadbmodel.VM,
		metadbmodel.VM,
		*message.AddedVMs,
		message.AddedVMs,
		message.AddNoneAddition,
		*message.UpdatedVM,
		message.UpdatedVM,
		*message.UpdatedVMFields,
		message.UpdatedVMFields,
		*message.DeletedVMs,
		message.DeletedVMs,
		message.DeleteNoneAddition]
}

func NewVM(wholeCache *cache.Cache, cloudData []cloudmodel.VM) *VM {
	updater := &VM{
		newUpdaterBase[
			cloudmodel.VM,
			*diffbase.VM,
			*metadbmodel.VM,
			metadbmodel.VM,
			*message.AddedVMs,
			message.AddedVMs,
			message.AddNoneAddition,
			*message.UpdatedVM,
			message.UpdatedVM,
			*message.UpdatedVMFields,
			message.UpdatedVMFields,
			*message.DeletedVMs,
			message.DeletedVMs,
			message.DeleteNoneAddition,
		](
			ctrlrcommon.RESOURCE_TYPE_VM_EN,
			wholeCache,
			db.NewVM().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.VMs,
			cloudData,
		),
	}
	updater.dataGenerator = updater
	return updater
}

func (m *VM) generateDBItemToAdd(cloudItem *cloudmodel.VM) (*metadbmodel.VM, bool) {
	vpcID, exists := m.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
	if !exists {
		log.Error(resourceAForResourceBNotFound(
			ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
			ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.Lcuuid,
		), m.metadata.LogPrefixes)
		return nil, false
	}
	var hostID int
	if cloudItem.LaunchServer != "" {
		hostID, _ = m.cache.ToolDataSet.GetHostIDByIP(cloudItem.LaunchServer)
	}
	cloudTags := map[string]string{}
	if cloudItem.CloudTags != nil {
		cloudTags = cloudItem.CloudTags
	}
	networkID := 0
	if cloudItem.NetworkLcuuid != "" {
		networkID, exists = m.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
				ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.Lcuuid,
			), m.metadata.LogPrefixes)
		}
	}
	if cloudItem.Label == "" {
		cloudItem.Label = ctrlrcommon.GenerateResourceShortUUID(ctrlrcommon.RESOURCE_TYPE_CHOST_EN)
	}
	dbItem := &metadbmodel.VM{
		Name:             cloudItem.Name,
		Label:            cloudItem.Label,
		IP:               cloudItem.IP,
		Hostname:         cloudItem.Hostname,
		UID:              cloudItem.Label,
		State:            cloudItem.State,
		HType:            cloudItem.HType,
		LaunchServer:     cloudItem.LaunchServer,
		HostID:           hostID,
		Domain:           m.metadata.GetDomainLcuuid(),
		Region:           cloudItem.RegionLcuuid,
		AZ:               cloudItem.AZLcuuid,
		VPCID:            vpcID,
		LearnedCloudTags: cloudTags,
		CustomCloudTags:  make(map[string]string),
		NetworkID:        networkID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	if !cloudItem.CreatedAt.IsZero() {
		dbItem.CreatedAt = cloudItem.CreatedAt
		m.recordStatsd(cloudItem)
	}
	return dbItem, true
}

func (m *VM) recordStatsd(cloudItem *cloudmodel.VM) {
	syncDelay := time.Since(cloudItem.CreatedAt).Seconds()
	m.statsd.GetMonitor(statsd.TagTypeVMSyncDelay).Fill(int(syncDelay))
}

func (m *VM) generateUpdateInfo(diffBase *diffbase.VM, cloudItem *cloudmodel.VM) (*message.UpdatedVMFields, map[string]interface{}, bool) {
	structInfo := new(message.UpdatedVMFields)
	mapInfo := make(map[string]interface{})
	if diffBase.VPCLcuuid != cloudItem.VPCLcuuid {
		vpcID, exists := m.cache.ToolDataSet.GetVPCIDByLcuuid(cloudItem.VPCLcuuid)
		if !exists {
			log.Error(resourceAForResourceBNotFound(
				ctrlrcommon.RESOURCE_TYPE_VPC_EN, cloudItem.VPCLcuuid,
				ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.Lcuuid,
			), m.metadata.LogPrefixes)
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

	if cloudItem.Label == "" {
		if diffBase.Label == "" {
			cloudItem.Label = ctrlrcommon.GenerateResourceShortUUID(ctrlrcommon.RESOURCE_TYPE_CHOST_EN)
		} else {
			cloudItem.Label = diffBase.Label
		}
	}
	if diffBase.Label != cloudItem.Label {
		mapInfo["label"] = cloudItem.Label
		structInfo.Label.Set(diffBase.Label, cloudItem.Label)
	}
	if diffBase.IP != cloudItem.IP {
		mapInfo["ip"] = cloudItem.IP
		structInfo.IP.Set(diffBase.IP, cloudItem.IP)
	}
	if diffBase.Hostname != cloudItem.Hostname {
		mapInfo["hostname"] = cloudItem.Hostname
		structInfo.Hostname.Set(diffBase.Hostname, cloudItem.Hostname)
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
	if cloudItem.LaunchServer != "" {
		hostID, _ := m.cache.ToolDataSet.GetHostIDByIP(cloudItem.LaunchServer)
		if diffBase.HostID != hostID {
			mapInfo["host_id"] = hostID
			structInfo.HostID.Set(diffBase.HostID, hostID)
		}
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.AZLcuuid != cloudItem.AZLcuuid {
		mapInfo["az"] = cloudItem.AZLcuuid
		structInfo.AZLcuuid.Set(diffBase.AZLcuuid, cloudItem.AZLcuuid)
	}
	if cloudcommon.DiffMap(diffBase.LearnedCloudTags, cloudItem.CloudTags) {
		updateTags := map[string]string{}
		if cloudItem.CloudTags != nil {
			updateTags = cloudItem.CloudTags
		}
		tagsJson, _ := json.Marshal(updateTags)
		mapInfo["learned_cloud_tags"] = tagsJson
		structInfo.LearnedCloudTags.Set(diffBase.LearnedCloudTags, cloudItem.CloudTags)
	}
	if diffBase.NetworkLcuuid != cloudItem.NetworkLcuuid {
		networkID := 0
		if cloudItem.NetworkLcuuid != "" {
			var exists bool
			networkID, exists = m.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
			if !exists {
				log.Error(resourceAForResourceBNotFound(
					ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
					ctrlrcommon.RESOURCE_TYPE_VM_EN, cloudItem.Lcuuid,
				), m.metadata.LogPrefixes)
			}
		}
		mapInfo["vl2id"] = networkID
		structInfo.NetworkID.SetNew(networkID)
		structInfo.NetworkLcuuid.Set(diffBase.NetworkLcuuid, cloudItem.NetworkLcuuid)
	}

	return structInfo, mapInfo, len(mapInfo) > 0
}
