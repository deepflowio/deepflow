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

package event

import (
	"fmt"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type LANIP struct {
	EventManagerBase
}

func NewLANIP(toolDS *tool.DataSet, eq *queue.OverwriteQueue) *LANIP {
	mng := &LANIP{
		EventManagerBase{
			resourceType: ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
	}
	return mng
}

func (i *LANIP) ProduceByAdd(items []*mysql.LANIP) {
	for _, item := range items {
		var (
			deviceType        int
			deviceID          int
			mac               string
			deviceName        string
			networkID         int
			networkName       string
			opts              []eventapi.TagFieldOption
			deviceRelatedOpts []eventapi.TagFieldOption
		)

		vifLcuuid, ok := i.ToolDataSet.GetVInterfaceLcuuidByID(item.VInterfaceID)
		if ok {
			deviceType, ok = i.ToolDataSet.GetDeviceTypeByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("device type for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
			}
			deviceID, ok = i.ToolDataSet.GetDeviceIDByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("device id for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
			}
			mac, ok = i.ToolDataSet.GetMacByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("mac for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
			}
			var err error
			deviceName, err = i.ToolDataSet.GetDeviceNameByDeviceID(deviceType, deviceID)
			if err != nil {
				log.Errorf("device name for %s (lcuuid: %s) not found, %v", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, err)
			}
			deviceRelatedOpts, err = GetDeviceOptionsByDeviceID(i.ToolDataSet, deviceType, deviceID)
			if err != nil {
				log.Errorf("releated options for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, err)
			}
			networkID, ok = i.ToolDataSet.GetNetworkIDByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("network id for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
			}
			networkName, ok = i.ToolDataSet.GetNetworkNameByID(networkID)
			if !ok {
				log.Errorf("network name for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
			}
		} else {
			log.Errorf("%s lcuuid (id: %d) for %s not found",
				ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, item.VInterfaceID, ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN)
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagDescription(fmt.Sprintf(DESCAddIPFormat, deviceName, item.IP, mac, networkName)),
			eventapi.TagAttributeSubnetIDs([]uint32{uint32(networkID)}),
			eventapi.TagAttributeIPs([]string{item.IP}),
			eventapi.TagSubnetID(uint32(networkID)),
			eventapi.TagIP(item.IP),
		}...)
		opts = append(opts, deviceRelatedOpts...)

		if deviceType == ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE {
			podNodeInfo, err := i.ToolDataSet.GetPodNodeInfoByID(deviceID)
			if err != nil {
				log.Error(err)
			} else {
				l3DeviceOpts, ok := getL3DeviceOptionsByPodNodeID(i.ToolDataSet, deviceID)
				if ok {
					opts = append(opts, l3DeviceOpts...)
				} else {
					i.enqueueIfInsertIntoMySQLFailed(
						item.Lcuuid,
						podNodeInfo.DomainLcuuid,
						eventapi.RESOURCE_EVENT_TYPE_ADD_IP,
						deviceName,
						deviceType,
						deviceID,
						opts...,
					)
					continue
				}
			}
		} else if deviceType == ctrlrcommon.VIF_DEVICE_TYPE_POD {
			podInfo, err := i.ToolDataSet.GetPodInfoByID(deviceID)
			if err != nil {
				log.Error(err)
			} else {
				l3DeviceOpts, ok := getL3DeviceOptionsByPodNodeID(i.ToolDataSet, podInfo.PodNodeID)
				if ok {
					opts = append(opts, l3DeviceOpts...)
				} else {
					i.enqueueIfInsertIntoMySQLFailed(
						item.Lcuuid,
						podInfo.DomainLcuuid,
						eventapi.RESOURCE_EVENT_TYPE_ADD_IP,
						deviceName,
						deviceType,
						deviceID,
						opts...,
					)
					continue
				}
			}
		}

		i.createAndEnqueue(
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_ADD_IP,
			deviceName,
			deviceType,
			deviceID,
			opts...,
		)
	}
}

func (i *LANIP) ProduceByUpdate(items *cloudmodel.IP, diffBase *diffbase.LANIP) {
}

func (i *LANIP) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var deviceType int
		var deviceID int
		var mac string
		var deviceName string
		var networkID int
		var networkName string
		var err error
		vifID, ok := i.ToolDataSet.GetVInterfaceIDByLANIPLcuuid(lcuuid)
		if ok {
			vifLcuuid, ok := i.ToolDataSet.GetVInterfaceLcuuidByID(vifID)
			if ok {
				deviceType, ok = i.ToolDataSet.GetDeviceTypeByVInterfaceLcuuid(vifLcuuid)
				if !ok {
					log.Errorf("device type for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
				}
				deviceID, ok = i.ToolDataSet.GetDeviceIDByVInterfaceLcuuid(vifLcuuid)
				if !ok {
					log.Errorf("device id for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
				}
				mac, ok = i.ToolDataSet.GetMacByVInterfaceLcuuid(vifLcuuid)
				if !ok {
					log.Errorf("mac for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
				}
				deviceName, err = i.ToolDataSet.GetDeviceNameByDeviceID(deviceType, deviceID)
				if err != nil {
					log.Errorf("device name for %s (lcuuid: %s) not found, %v", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, err)
					deviceName = getDeviceNameFromAllByID(deviceType, deviceID)
				}
				networkID, ok = i.ToolDataSet.GetNetworkIDByVInterfaceLcuuid(vifLcuuid)
				if !ok {
					log.Errorf("network id for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
				}
				networkName, ok = i.ToolDataSet.GetNetworkNameByID(networkID)
				if !ok {
					log.Errorf("network name for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid)
				}
			} else {
				log.Errorf("%s lcuuid (id: %d) for %s not found",
					ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifID, ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN)
			}
		} else {
			log.Errorf("%s id for %s (lcuuid: %s) not found",
				ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, lcuuid)
		}

		ip, ok := i.ToolDataSet.GetLANIPByLcuuid(lcuuid)
		if !ok {
			log.Error("%s (lcuuid: %s) ip not found", ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, lcuuid)
		}

		i.createAndEnqueue(
			lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_REMOVE_IP,
			deviceName,
			deviceType,
			deviceID,
			eventapi.TagDescription(fmt.Sprintf(DESCRemoveIPFormat, deviceName, ip, mac, networkName)),
			eventapi.TagAttributeSubnetIDs([]uint32{uint32(networkID)}),
			eventapi.TagAttributeIPs([]string{ip}),
			eventapi.TagSubnetID(uint32(networkID)),
			eventapi.TagIP(ip),
		)
	}
}
