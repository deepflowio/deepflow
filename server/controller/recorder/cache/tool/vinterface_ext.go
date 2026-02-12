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

package tool

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type VinterfaceExt struct {
	deviceName string
}

func (item *Vinterface) resetExt(dbItem *metadbmodel.VInterface, tool *Tool) {
	// Handle deviceName custom logic
	switch dbItem.DeviceType {
	case ctrlrcommon.VIF_DEVICE_TYPE_HOST:
		item.deviceName = tool.Host().GetById(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_VM:
		item.deviceName = tool.Vm().GetById(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_VROUTER:
		item.deviceName = tool.Vrouter().GetById(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		item.deviceName = tool.DhcpPort().GetById(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		item.deviceName = tool.NatGateway().GetById(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_LB:
		item.deviceName = tool.Lb().GetById(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		item.deviceName = tool.RdsInstance().GetById(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		item.deviceName = tool.RedisInstance().GetById(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE:
		item.deviceName = tool.PodNode().GetById(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		item.deviceName = tool.PodService().GetById(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD:
		item.deviceName = tool.Pod().GetById(dbItem.DeviceID).Name()
	}
}

type deviceKey struct {
	dType int
	id    int
}

type VinterfaceCollectionExt struct {
	deviceKeyToItems map[deviceKey][]*Vinterface
}

func (ext *VinterfaceCollection) resetExt() {
	ext.deviceKeyToItems = make(map[deviceKey][]*Vinterface)
}

func (ext *VinterfaceCollection) GetByDeviceKey(deviceType, deviceID int) []*Vinterface {
	return ext.deviceKeyToItems[deviceKey{
		dType: deviceType,
		id:    deviceID,
	}]
}

func (ext *VinterfaceCollection) OnAfterAdd(item *Vinterface, dbItem *metadbmodel.VInterface) {
	dk := deviceKey{
		dType: dbItem.DeviceType,
		id:    dbItem.DeviceID,
	}
	ext.deviceKeyToItems[dk] = append(ext.deviceKeyToItems[dk], item)
}

func (ext *VinterfaceCollection) OnAfterUpdate(item *Vinterface, dbItem *metadbmodel.VInterface) {
	// For connection tables, update is usually just add/delete operations
	// No special logic needed for update
}

func (ext *VinterfaceCollection) OnAfterDelete(item *Vinterface, dbItem *metadbmodel.VInterface) {
	dk := deviceKey{
		dType: dbItem.DeviceType,
		id:    dbItem.DeviceID,
	}
	for i, v := range ext.deviceKeyToItems[dk] {
		if v.Id() == dbItem.ID {
			ext.deviceKeyToItems[dk] = append(ext.deviceKeyToItems[dk][:i], ext.deviceKeyToItems[dk][i+1:]...)
			break
		}
	}
}
