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

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type LANIP struct {
	ManagerComponent
	CUDSubscriberComponent
	tool *IPTool
}

func NewLANIP(q *queue.OverwriteQueue) *LANIP {
	mng := &LANIP{
		newManagerComponent(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, q),
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN),
		newTool(),
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (i *LANIP) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.LANIP) {
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

		vifLcuuid, ok := md.GetToolDataSet().GetVInterfaceLcuuidByID(item.VInterfaceID)
		if ok {
			deviceType, ok = md.GetToolDataSet().GetDeviceTypeByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("device type for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, md.LogPrefixORGID)
			}
			deviceID, ok = md.GetToolDataSet().GetDeviceIDByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("device id for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, md.LogPrefixORGID)
			}
			mac, ok = md.GetToolDataSet().GetMacByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("mac for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, md.LogPrefixORGID)
			}
			var err error
			deviceName, err = md.GetToolDataSet().GetDeviceNameByDeviceID(deviceType, deviceID)
			if err != nil {
				log.Errorf("device name for %s (lcuuid: %s) not found, %v", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, err, md.LogPrefixORGID)
			}
			deviceRelatedOpts, err = i.tool.GetDeviceOptionsByDeviceID(md, deviceType, deviceID)
			if err != nil {
				log.Errorf("releated options for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, md.LogPrefixORGID)
			}
			networkID, ok = md.GetToolDataSet().GetNetworkIDByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("network id for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, md.LogPrefixORGID)
			}
			networkName, ok = md.GetToolDataSet().GetNetworkNameByID(networkID)
			if !ok {
				log.Errorf("network name for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, md.LogPrefixORGID)
			}
		} else {
			log.Errorf("%s lcuuid (id: %d) for %s not found",
				ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, item.VInterfaceID, ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, md.LogPrefixORGID)
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
			podNodeInfo, err := md.GetToolDataSet().GetPodNodeInfoByID(deviceID)
			if err != nil {
				log.Error(err)
			} else {
				l3DeviceOpts, ok := i.tool.getL3DeviceOptionsByPodNodeID(md, deviceID)
				if ok {
					opts = append(opts, l3DeviceOpts...)
				} else {
					i.enqueueIfInsertIntoMySQLFailed(
						md,
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
			podInfo, err := md.GetToolDataSet().GetPodInfoByID(deviceID)
			if err != nil {
				log.Error(err)
			} else {
				l3DeviceOpts, ok := i.tool.getL3DeviceOptionsByPodNodeID(md, podInfo.PodNodeID)
				if ok {
					opts = append(opts, l3DeviceOpts...)
				} else {
					i.enqueueIfInsertIntoMySQLFailed(
						md,
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

		i.createAndEnqueue(md,
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_ADD_IP,
			deviceName,
			deviceType,
			deviceID,
			opts...,
		)
	}
}

func (i *LANIP) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.LANIP) {
		var deviceType int
		var deviceID int
		var mac string
		var deviceName string
		var networkID int
		var networkName string
		var err error
		vifID := item.VInterfaceID
		ip := item.IP
		vifLcuuid, ok := md.GetToolDataSet().GetVInterfaceLcuuidByID(vifID)
		if ok {
			deviceType, ok = md.GetToolDataSet().GetDeviceTypeByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("device type for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, md.LogPrefixORGID)
			}
			deviceID, ok = md.GetToolDataSet().GetDeviceIDByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("device id for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, md.LogPrefixORGID)
			}
			mac, ok = md.GetToolDataSet().GetMacByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("mac for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, md.LogPrefixORGID)
			}
			deviceName, err = md.GetToolDataSet().GetDeviceNameByDeviceID(deviceType, deviceID)
			if err != nil {
				log.Errorf("device name for %s (lcuuid: %s) not found, %v", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, err, md.LogPrefixORGID)
				deviceName = i.tool.getDeviceNameFromAllByID(md, deviceType, deviceID)
			}
			networkID, ok = md.GetToolDataSet().GetNetworkIDByVInterfaceLcuuid(vifLcuuid)
			if !ok {
				log.Errorf("network id for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, md.LogPrefixORGID)
			}
			networkName, ok = md.GetToolDataSet().GetNetworkNameByID(networkID)
			if !ok {
				log.Errorf("network name for %s (lcuuid: %s) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifLcuuid, md.LogPrefixORGID)
			}
		} else {
			log.Errorf("%s lcuuid (id: %d) for %s not found",
				ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifID, ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN, md.LogPrefixORGID)
		}

		i.createAndEnqueue(md,
			item.Lcuuid,
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
