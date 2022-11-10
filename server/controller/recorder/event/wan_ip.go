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

	cloudmodel "github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	. "github.com/deepflowys/deepflow/server/controller/recorder/common"
	"github.com/deepflowys/deepflow/server/libs/eventapi"
	"github.com/deepflowys/deepflow/server/libs/queue"
)

type WANIP struct {
	EventManager[cloudmodel.IP, mysql.WANIP, *cache.WANIP]
}

func NewWANIP(toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *WANIP {
	mng := &WANIP{
		EventManager[cloudmodel.IP, mysql.WANIP, *cache.WANIP]{
			resourceType: RESOURCE_TYPE_WAN_IP_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
	}
	return mng
}

func (i *WANIP) ProduceByAdd(items []*mysql.WANIP) {
	for _, item := range items {
		var (
			deviceType        int
			deviceID          int
			deviceName        string
			networkID         int
			networkName       string
			opts              []eventapi.TagFieldOption
			deviceRelatedOpts []eventapi.TagFieldOption
			err               error
		)

		vifLcuuid, ok := i.ToolDataSet.GetVInterfaceLcuuidByID(item.VInterfaceID)
		if ok {
			deviceType, ok = i.ToolDataSet.GetDeviceTypeByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("device type for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
			}
			deviceID, ok = i.ToolDataSet.GetDeviceIDByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("device id for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
			}
			deviceName, err = i.ToolDataSet.GetDeviceNameByDeviceID(deviceType, deviceID)
			if err != nil {
				log.Error(err)
			}
			deviceRelatedOpts, err = GetDeviceOptionsByDeviceID(i.ToolDataSet, deviceType, deviceID)
			if err != nil {
				log.Error(err)
			}
			networkID, ok = i.ToolDataSet.GetNetworkIDByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("network id for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
			}
			networkName, ok = i.ToolDataSet.GetNetworkNameByID(networkID)
			if !ok {
				log.Errorf("network name for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
			}
		} else {
			log.Errorf("%s lcuuid (id: %d) for %s not found", RESOURCE_TYPE_VINTERFACE_EN, item.VInterfaceID, RESOURCE_TYPE_WAN_IP_EN)
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagDescription(fmt.Sprintf("%s-%s", networkName, item.IP)),
			eventapi.TagSubnetIDs([]uint32{uint32(networkID)}),
			eventapi.TagIPs([]string{item.IP}),
		}...)
		opts = append(opts, deviceRelatedOpts...)

		i.createAndPutEvent(
			eventapi.RESOURCE_EVENT_TYPE_ADD_IP,
			deviceName,
			deviceType,
			deviceID,
			opts...,
		)
	}
}

func (i *WANIP) ProduceByUpdate(cloudItem *cloudmodel.IP, diffBase *cache.WANIP) {
}

func (i *WANIP) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var (
			deviceType  int
			deviceID    int
			deviceName  string
			networkID   int
			networkName string
			opts        []eventapi.TagFieldOption
			tempOpts    []eventapi.TagFieldOption
			err         error
		)
		vifID, ok := i.ToolDataSet.GetVInterfaceIDByWANIPLcuuid(lcuuid)
		if ok {
			vifLcuuid, ok := i.ToolDataSet.GetVInterfaceLcuuidByID(vifID)
			if ok {
				deviceType, ok = i.ToolDataSet.GetDeviceTypeByVInterfaceLcuuid(vifLcuuid)
				if !ok {
					log.Errorf("device type for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
				}
				deviceID, ok = i.ToolDataSet.GetDeviceIDByVInterfaceLcuuid(vifLcuuid)
				if !ok {
					log.Errorf("device id for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
				}
				deviceName, err = i.ToolDataSet.GetDeviceNameByDeviceID(deviceType, deviceID)
				if err != nil {
					log.Error(err)
				}
				var err error
				tempOpts, err = GetDeviceOptionsByDeviceID(i.ToolDataSet, deviceType, deviceID)
				if err != nil {
					log.Errorf("device name for %s (lcuuid: %s) not found, %v", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, err)
				}
				networkID, ok = i.ToolDataSet.GetNetworkIDByVInterfaceLcuuid(vifLcuuid)
				if !ok {
					log.Errorf("network id for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
				}
				networkName, ok = i.ToolDataSet.GetNetworkNameByID(networkID)
				if !ok {
					log.Errorf("network name for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
				}

			} else {
				log.Errorf("%s lcuuid (id: %d) for %s not found", RESOURCE_TYPE_VINTERFACE_EN, vifID, RESOURCE_TYPE_WAN_IP_EN)
			}
		} else {
			log.Errorf("%s id for %s (lcuuid: %s) not found", RESOURCE_TYPE_VINTERFACE_EN, RESOURCE_TYPE_WAN_IP_EN, lcuuid)
		}

		ip, ok := i.ToolDataSet.GetWANIPByLcuuid(lcuuid)
		if !ok {
			log.Errorf("%s (lcuuid: %s) ip not found", RESOURCE_TYPE_WAN_IP_EN, lcuuid)
		}

		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagDescription(fmt.Sprintf("%s-%s", networkName, ip)),
			eventapi.TagSubnetIDs([]uint32{uint32(networkID)}),
			eventapi.TagIPs([]string{ip}),
		}...)
		opts = append(opts, tempOpts...)

		i.createAndPutEvent(
			eventapi.RESOURCE_EVENT_TYPE_REMOVE_IP,
			deviceName,
			deviceType,
			deviceID,
			opts...,
		)
	}
}
