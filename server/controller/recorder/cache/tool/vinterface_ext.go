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

func (item *VInterface) resetCustom(dbItem *metadbmodel.VInterface, tool *Tool) {
	// Handle deviceName custom logic
	switch dbItem.DeviceType {
	case ctrlrcommon.VIF_DEVICE_TYPE_HOST:
		item.deviceName = tool.Host().GetByID(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_VM:
		item.deviceName = tool.VM().GetByID(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_VROUTER:
		item.deviceName = tool.VRouter().GetByID(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		item.deviceName = tool.DHCPPort().GetByID(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		item.deviceName = tool.NATGateway().GetByID(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_LB:
		item.deviceName = tool.LB().GetByID(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		item.deviceName = tool.RDSInstance().GetByID(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		item.deviceName = tool.RedisInstance().GetByID(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE:
		item.deviceName = tool.PodNode().GetByID(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		item.deviceName = tool.PodService().GetByID(dbItem.DeviceID).Name()
	case ctrlrcommon.VIF_DEVICE_TYPE_POD:
		item.deviceName = tool.Pod().GetByID(dbItem.DeviceID).Name()
	}
}

type deviceKey struct {
	dType int
	id    int
}

type VInterfaceCollectionExt struct {
	deviceKeyToItems map[deviceKey][]*VInterface
}

func (ext *VInterfaceCollection) resetExt() {
	ext.deviceKeyToItems = make(map[deviceKey][]*VInterface)
}

func (ext *VInterfaceCollection) GetByDeviceKey(deviceType, deviceID int) []*VInterface {
	return ext.deviceKeyToItems[deviceKey{
		dType: deviceType,
		id:    deviceID,
	}]
}

func (ext *VInterfaceCollection) OnAfterAdd(item *VInterface, dbItem *metadbmodel.VInterface) {
	dk := deviceKey{
		dType: dbItem.DeviceType,
		id:    dbItem.DeviceID,
	}
	ext.deviceKeyToItems[dk] = append(ext.deviceKeyToItems[dk], item)
}

func (ext *VInterfaceCollection) OnAfterUpdate(item *VInterface, dbItem *metadbmodel.VInterface) {
	// For connection tables, update is usually just add/delete operations
	// No special logic needed for update
}

func (ext *VInterfaceCollection) OnAfterDelete(item *VInterface, dbItem *metadbmodel.VInterface) {
	dk := deviceKey{
		dType: dbItem.DeviceType,
		id:    dbItem.DeviceID,
	}
	for i, v := range ext.deviceKeyToItems[dk] {
		if v.ID() == dbItem.ID {
			ext.deviceKeyToItems[dk] = append(ext.deviceKeyToItems[dk][:i], ext.deviceKeyToItems[dk][i+1:]...)
			break
		}
	}
}
