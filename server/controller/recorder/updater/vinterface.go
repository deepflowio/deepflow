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
	"strings"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
)

type VInterface struct {
	UpdaterBase[
		cloudmodel.VInterface,
		*diffbase.VInterface,
		*mysqlmodel.VInterface,
		mysqlmodel.VInterface,
		*message.VInterfaceAdd,
		message.VInterfaceAdd,
		*message.VInterfaceUpdate,
		message.VInterfaceUpdate,
		*message.VInterfaceFieldsUpdate,
		message.VInterfaceFieldsUpdate,
		*message.VInterfaceDelete,
		message.VInterfaceDelete]
}

func NewVInterface(wholeCache *cache.Cache, cloudData []cloudmodel.VInterface, domainToolDataSet *tool.DataSet) *VInterface {
	updater := &VInterface{
		newUpdaterBase[
			cloudmodel.VInterface,
			*diffbase.VInterface,
			*mysqlmodel.VInterface,
			mysqlmodel.VInterface,
			*message.VInterfaceAdd,
			message.VInterfaceAdd,
			*message.VInterfaceUpdate,
			message.VInterfaceUpdate,
			*message.VInterfaceFieldsUpdate,
			message.VInterfaceFieldsUpdate,
			*message.VInterfaceDelete,
		](
			ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN,
			wholeCache,
			db.NewVInterface().SetMetadata(wholeCache.GetMetadata()),
			wholeCache.DiffBaseDataSet.VInterfaces,
			cloudData,
		),
	}
	updater.setDomainToolDataSet(domainToolDataSet)
	updater.dataGenerator = updater
	return updater
}

func (i *VInterface) getDiffBaseByCloudItem(cloudItem *cloudmodel.VInterface) (diffBase *diffbase.VInterface, exists bool) {
	diffBase, exists = i.diffBaseData[cloudItem.Lcuuid]
	return
}

func (i *VInterface) generateDBItemToAdd(cloudItem *cloudmodel.VInterface) (*mysqlmodel.VInterface, bool) {
	var networkID int
	if cloudItem.NetworkLcuuid != "" {
		var exists bool
		networkID, exists = i.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
		if !exists {
			if i.domainToolDataSet != nil {
				networkID, exists = i.domainToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
			}
			if !exists {
				log.Error(resourceAForResourceBNotFound(
					ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
					ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.Lcuuid,
				), i.metadata.LogPrefixes)
				return nil, false
			}
		}
	}
	deviceID, exists := i.cache.ToolDataSet.GetDeviceIDByDeviceLcuuid(cloudItem.DeviceType, cloudItem.DeviceLcuuid)
	if !exists {
		log.Errorf(
			"device (type: %d, lcuuid: %s) for %s (lcuuid: %s) not found",
			cloudItem.DeviceType, cloudItem.DeviceLcuuid,
			ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.Lcuuid,
			i.metadata.LogPrefixes)
		return nil, false
	}

	dbItem := &mysqlmodel.VInterface{
		Name:       cloudItem.Name,
		Type:       cloudItem.Type,
		State:      1,
		NetworkID:  networkID,
		Mac:        strings.ToLower(cloudItem.Mac),
		TapMac:     strings.ToLower(cloudItem.TapMac),
		DeviceType: cloudItem.DeviceType,
		DeviceID:   deviceID,
		VlanTag:    0,
		SubDomain:  cloudItem.SubDomainLcuuid,
		Domain:     i.metadata.Domain.Lcuuid,
		Region:     cloudItem.RegionLcuuid,
		NetnsID:    cloudItem.NetnsID,
		VtapID:     cloudItem.VTapID,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (i *VInterface) generateUpdateInfo(diffBase *diffbase.VInterface, cloudItem *cloudmodel.VInterface) (*message.VInterfaceFieldsUpdate, map[string]interface{}, bool) {
	structInfo := new(message.VInterfaceFieldsUpdate)
	mapInfo := make(map[string]interface{})
	if diffBase.NetworkLcuuid != cloudItem.NetworkLcuuid {
		if cloudItem.NetworkLcuuid == "" {
			mapInfo["subnetid"] = 0
		} else {
			networkID, exists := i.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
			if !exists {
				if i.domainToolDataSet != nil {
					networkID, exists = i.domainToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
				}
				if !exists {
					log.Error(resourceAForResourceBNotFound(
						ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
						ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.Lcuuid,
					), i.metadata.LogPrefixes)
					return nil, nil, false
				}
			}
			mapInfo["subnetid"] = networkID
		}
		structInfo.NetworkID.SetNew(mapInfo["subnetid"].(int))
		structInfo.NetworkLcuuid.Set(diffBase.NetworkLcuuid, cloudItem.NetworkLcuuid)
	}
	if diffBase.DeviceLcuuid != cloudItem.DeviceLcuuid {
		deviceID, exists := i.cache.ToolDataSet.GetDeviceIDByDeviceLcuuid(cloudItem.DeviceType, cloudItem.DeviceLcuuid)
		if !exists {
			log.Errorf(resourceAForResourceBNotFound(
				common.VIF_DEVICE_TYPE_TO_RESOURCE_TYPE[cloudItem.DeviceType], cloudItem.DeviceLcuuid,
				common.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.Lcuuid,
			))
			return nil, nil, false
		}
		mapInfo["deviceid"] = deviceID
	}
	if diffBase.Name != cloudItem.Name {
		mapInfo["name"] = cloudItem.Name
		structInfo.Name.Set(diffBase.Name, cloudItem.Name)
	}
	if diffBase.TapMac != cloudItem.TapMac {
		mapInfo["tap_mac"] = cloudItem.TapMac
		structInfo.TapMac.Set(diffBase.TapMac, cloudItem.TapMac)
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		mapInfo["region"] = cloudItem.RegionLcuuid
		structInfo.RegionLcuuid.Set(diffBase.RegionLcuuid, cloudItem.RegionLcuuid)
	}
	if diffBase.Type != cloudItem.Type {
		mapInfo["iftype"] = cloudItem.Type
		structInfo.Type.Set(diffBase.Type, cloudItem.Type)
	}
	if diffBase.NetnsID != cloudItem.NetnsID {
		mapInfo["netns_id"] = cloudItem.NetnsID
		structInfo.NetnsID.Set(diffBase.NetnsID, cloudItem.NetnsID)
	}
	if diffBase.VtapID != cloudItem.VTapID {
		mapInfo["vtap_id"] = cloudItem.VTapID
		structInfo.VTapID.Set(diffBase.VtapID, cloudItem.VTapID)
	}
	return structInfo, mapInfo, len(mapInfo) > 0
}
