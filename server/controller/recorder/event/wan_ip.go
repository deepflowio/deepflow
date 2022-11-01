/*
 * Copyright (c) 2022 Yunshan Networks
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
	"time"

	cloudmodel "github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	. "github.com/deepflowys/deepflow/server/controller/recorder/common"
	"github.com/deepflowys/deepflow/server/libs/eventapi"
	"github.com/deepflowys/deepflow/server/libs/queue"
)

type WANIP struct {
	EventManager[cloudmodel.IP, mysql.WANIP]
}

func NewWANIP(toolDS cache.ToolDataSet, eq *queue.OverwriteQueue) *WANIP {
	mng := &WANIP{
		EventManager[cloudmodel.IP, mysql.WANIP]{
			resourceType: RESOURCE_TYPE_WAN_IP_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
	}
	return mng
}

func (i *WANIP) ProduceByAdd(items []*mysql.WANIP) {
	for _, item := range items {
		var deviceInfo *cache.DeviceInfo
		var networkInfo *cache.NetworkInfo
		vifLcuuid, ok := i.ToolDataSet.GetVInterfaceLcuuidByID(item.VInterfaceID)
		if ok {
			deviceInfo, ok = i.ToolDataSet.GetDeviceInfoByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("device info for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
			}
			networkInfo, ok = i.ToolDataSet.GetNetworkInfoByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Error("network info for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
			}
		} else {
			log.Errorf("%s lcuuid (id: %d) for %s not found", RESOURCE_TYPE_VINTERFACE_EN, item.VInterfaceID, RESOURCE_TYPE_WAN_IP_EN)
		}

		event := i.createEvent()
		event.Time = time.Now().Unix()
		event.Type = eventapi.RESOURCE_EVENT_TYPE_ADD_IP
		event.ResourceType = uint32(deviceInfo.Type)
		event.ResourceID = uint32(deviceInfo.ID)
		event.ResourceName = deviceInfo.Name
		event.Description = fmt.Sprintf("%s-%s", networkInfo.Name, item.IP)
		i.put(event)
	}
}

func (i *WANIP) ProduceByUpdate(items *cloudmodel.IP) {
}

func (i *WANIP) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var deviceInfo *cache.DeviceInfo
		var networkInfo *cache.NetworkInfo
		vifID, ok := i.ToolDataSet.GetVInterfaceIDByWANIPLcuuid(lcuuid)
		if ok {
			vifLcuuid, ok := i.ToolDataSet.GetVInterfaceLcuuidByID(vifID)
			if ok {
				deviceInfo, ok = i.ToolDataSet.GetDeviceInfoByVInterfaceLcuuid(vifLcuuid)
				if !ok {
					log.Errorf("device info for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
				}
				networkInfo, ok = i.ToolDataSet.GetNetworkInfoByVInterfaceLcuuid(vifLcuuid)
				if !ok {
					log.Error("network info for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
				}
			} else {
				log.Errorf("%s lcuuid (id: %d) for %s not found", RESOURCE_TYPE_VINTERFACE_EN, vifID, RESOURCE_TYPE_WAN_IP_EN)
			}
		} else {
			log.Errorf("%s id for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, RESOURCE_TYPE_WAN_IP_EN, lcuuid)
		}
		ip, ok := i.ToolDataSet.GetWANIPByLcuuid(lcuuid)
		if !ok {
			log.Error("%s (lcuuid: %s) ip not found", RESOURCE_TYPE_WAN_IP_EN, lcuuid)
		}

		event := i.createEvent()
		event.Time = time.Now().Unix()
		event.Type = eventapi.RESOURCE_EVENT_TYPE_REMOVE_IP
		event.ResourceType = uint32(deviceInfo.Type)
		event.ResourceID = uint32(deviceInfo.ID)
		event.ResourceName = deviceInfo.Name
		event.Description = fmt.Sprintf("%s-%s", networkInfo.Name, ip)
		i.put(event)
	}
}
