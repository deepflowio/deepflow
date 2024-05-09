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
	"strings"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/deepflowio/deepflow/server/controller/recorder/db"
)

type VInterface struct {
	UpdaterBase[cloudmodel.VInterface, mysql.VInterface, *cache.VInterface]
}

func NewVInterface(wholeCache *cache.Cache, cloudData []cloudmodel.VInterface, domainToolDataSet *cache.ToolDataSet) *VInterface {
	updater := &VInterface{
		UpdaterBase[cloudmodel.VInterface, mysql.VInterface, *cache.VInterface]{
			cache:             wholeCache,
			domainToolDataSet: domainToolDataSet,
			dbOperator:        db.NewVInterface(),
			diffBaseData:      wholeCache.VInterfaces,
			cloudData:         cloudData,
		},
	}
	updater.dataGenerator = updater
	updater.cacheHandler = updater
	return updater
}

func (i *VInterface) getDiffBaseByCloudItem(cloudItem *cloudmodel.VInterface) (diffBase *cache.VInterface, exists bool) {
	diffBase, exists = i.diffBaseData[cloudItem.Lcuuid]
	return
}

func (i *VInterface) generateDBItemToAdd(cloudItem *cloudmodel.VInterface) (*mysql.VInterface, bool) {
	var networkID int
	if cloudItem.NetworkLcuuid != "" {
		var exists bool
		networkID, exists = i.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
		if !exists {
			if i.domainToolDataSet != nil {
				networkID, exists = i.domainToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
			}
			if !exists {
				log.Errorf(resourceAForResourceBNotFound(
					common.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
					common.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.Lcuuid,
				))
				return nil, false
			}
		}
	}
	deviceID, exists := i.cache.ToolDataSet.GetDeviceIDByDeviceLcuuid(cloudItem.DeviceType, cloudItem.DeviceLcuuid)
	if !exists {
		log.Errorf(
			"device (type: %d, lcuuid: %s) for %s (lcuuid: %s) not found",
			cloudItem.DeviceType, cloudItem.DeviceLcuuid,
			common.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.Lcuuid,
		)
		return nil, false
	}

	dbItem := &mysql.VInterface{
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
		Domain:     i.cache.DomainLcuuid,
		Region:     cloudItem.RegionLcuuid,
	}
	dbItem.Lcuuid = cloudItem.Lcuuid
	return dbItem, true
}

func (i *VInterface) generateUpdateInfo(diffBase *cache.VInterface, cloudItem *cloudmodel.VInterface) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if diffBase.NetworkLcuuid != cloudItem.NetworkLcuuid {
		if cloudItem.NetworkLcuuid == "" {
			updateInfo["subnetid"] = 0
		} else {
			networkID, exists := i.cache.ToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
			if !exists {
				if i.domainToolDataSet != nil {
					networkID, exists = i.domainToolDataSet.GetNetworkIDByLcuuid(cloudItem.NetworkLcuuid)
				}
				if !exists {
					log.Errorf(resourceAForResourceBNotFound(
						common.RESOURCE_TYPE_NETWORK_EN, cloudItem.NetworkLcuuid,
						common.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.Lcuuid,
					))
					return nil, false
				}
			}
			updateInfo["subnetid"] = networkID
		}
	}
	if cloudItem.DeviceType == ctrlrcommon.VIF_DEVICE_TYPE_VM {
		if diffBase.DeviceLcuuid != cloudItem.DeviceLcuuid {
			vmID, exists := i.cache.ToolDataSet.GetVMIDByLcuuid(cloudItem.DeviceLcuuid)
			if !exists {
				log.Errorf(resourceAForResourceBNotFound(
					common.RESOURCE_TYPE_VM_EN, cloudItem.DeviceLcuuid,
					common.RESOURCE_TYPE_VINTERFACE_EN, cloudItem.Lcuuid,
				))
				return nil, false
			}
			updateInfo["deviceid"] = vmID
		}
	}
	if diffBase.Name != cloudItem.Name {
		updateInfo["name"] = cloudItem.Name
	}
	if diffBase.TapMac != cloudItem.TapMac {
		updateInfo["tap_mac"] = cloudItem.TapMac
	}
	if diffBase.RegionLcuuid != cloudItem.RegionLcuuid {
		updateInfo["region"] = cloudItem.RegionLcuuid
	}
	if diffBase.Type != cloudItem.Type {
		updateInfo["iftype"] = cloudItem.Type
	}
	return updateInfo, len(updateInfo) > 0
}

func (i *VInterface) addCache(dbItems []*mysql.VInterface) {
	i.cache.AddVInterfaces(dbItems)
}

func (i *VInterface) updateCache(cloudItem *cloudmodel.VInterface, diffBase *cache.VInterface) {
	diffBase.Update(cloudItem)
	i.cache.UpdateVInterface(cloudItem)
}

func (i *VInterface) deleteCache(lcuuids []string) {
	i.cache.DeleteVInterfaces(lcuuids)
}
