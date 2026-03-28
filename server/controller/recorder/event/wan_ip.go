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

type WANIP struct {
	ManagerComponent
	CUDSubscriberComponent
	tool *IPTool
}

func NewWANIP(q *queue.OverwriteQueue) *WANIP {
	mng := &WANIP{
		newManagerComponent(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, q),
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN),
		newTool(),
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (i *WANIP) OnResourceBatchAdded(md *message.Metadata, msg interface{}) { // TODO 同 lan ip 合并 common 逻辑
	for _, item := range msg.([]*metadbmodel.WANIP) {
		var (
			deviceType        int
			deviceID          int
			mac               string
			deviceName        string
			networkID         int
			networkName       string
			opts              []eventapi.TagFieldOption
			deviceRelatedOpts []eventapi.TagFieldOption
			err               error
		)

		vifItem := md.GetToolDataSet().Vinterface().GetById(item.VInterfaceID)
		if vifItem.IsValid() {
			deviceType = vifItem.DeviceType()
			deviceID = vifItem.DeviceId()
			mac = vifItem.Mac()
			deviceName = vifItem.DeviceName()
			deviceRelatedOpts, err = i.tool.GetDeviceOptionsByDeviceID(md, deviceType, deviceID)
			if err != nil {
				log.Errorf("releated options for %s (id: %d) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, item.VInterfaceID, md.LogPrefixes)
			}
			networkID = vifItem.NetworkId()
			nwItem := md.GetToolDataSet().Network().GetById(networkID)
			if nwItem.IsValid() {
				networkName = nwItem.Name()
			} else {
				log.Errorf("network name for %s (id: %d) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, item.VInterfaceID, md.LogPrefixes)
			}
		} else {
			log.Errorf("%s (id: %d) for %s not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, item.VInterfaceID, ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, md.LogPrefixes)
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
			pnItem := md.GetToolDataSet().PodNode().GetById(deviceID)
			if !pnItem.IsValid() {
				log.Errorf("pod_node(id=%d) not found", deviceID, md.LogPrefixes)
			} else {
				l3DeviceOpts, ok := i.tool.getL3DeviceOptionsByPodNodeID(md, deviceID)
				if ok {
					opts = append(opts, l3DeviceOpts...)
				} else {
					i.enqueueInstanceIfInsertIntoMetadbFailed(
						md,
						item.Lcuuid,
						pnItem.DomainLcuuid(),
						eventapi.RESOURCE_EVENT_TYPE_ATTACH_IP,
						deviceName,
						deviceType,
						deviceID,
						opts...,
					)
					continue
				}
			}
		} else if deviceType == ctrlrcommon.VIF_DEVICE_TYPE_POD {
			podItem := md.GetToolDataSet().Pod().GetById(deviceID)
			if !podItem.IsValid() {
				log.Errorf("pod(id=%d) not found", deviceID, md.LogPrefixes)
			} else {
				l3DeviceOpts, ok := i.tool.getL3DeviceOptionsByPodNodeID(md, podItem.PodNodeId())
				if ok {
					opts = append(opts, l3DeviceOpts...)
				} else {
					i.enqueueInstanceIfInsertIntoMetadbFailed(
						md,
						item.Lcuuid,
						podItem.DomainLcuuid(),
						eventapi.RESOURCE_EVENT_TYPE_ATTACH_IP,
						deviceName,
						deviceType,
						deviceID,
						opts...,
					)
					continue
				}
			}
		}

		i.createInstanceAndEnqueue(md,
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_ATTACH_IP,
			deviceName,
			deviceType,
			deviceID,
			opts...,
		)
	}
}

func (i *WANIP) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.WANIP) {
		var (
			deviceType  int
			deviceID    int
			mac         string
			deviceName  string
			networkID   int
			networkName string
		)
		vifID := item.VInterfaceID
		ip := item.IP

		vifItem := md.GetToolDataSet().Vinterface().GetById(vifID)
		if vifItem.IsValid() {
			deviceType = vifItem.DeviceType()
			deviceID = vifItem.DeviceId()
			mac = vifItem.Mac()
			deviceName = vifItem.DeviceName()
			if deviceName == "" {
				deviceName = i.tool.getDeviceNameFromAllByID(md, deviceType, deviceID)
			}
			networkID = vifItem.NetworkId()
			nwItem := md.GetToolDataSet().Network().GetById(networkID)
			if nwItem.IsValid() {
				networkName = nwItem.Name()
			} else {
				log.Errorf("network name for %s (id: %d) not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifID, md.LogPrefixes)
			}

		} else {
			log.Errorf("%s (id: %d) for %s not found", ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, vifID, ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN, md.LogPrefixes)
		}

		i.createInstanceAndEnqueue(md,
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_DETACH_IP,
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
