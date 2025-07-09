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

	"github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/metadata"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type Process struct {
	ManagerComponent
	CUDSubscriberComponent
	deviceType int
	tool       *IPTool
}

func NewProcess(q *queue.OverwriteQueue) *Process {
	mng := &Process{
		newManagerComponent(common.RESOURCE_TYPE_PROCESS_EN, q),
		newCUDSubscriberComponent(common.RESOURCE_TYPE_PROCESS_EN),
		common.PROCESS_INSTANCE_TYPE,
		newTool(),
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (p *Process) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	items := msg.([]*metadbmodel.Process)
	for _, item := range items {
		vtapName, ok := md.GetToolDataSet().GetVTapNameByID(int(item.VTapID))
		if !ok {
			log.Errorf("vtap name not found for vtap id %d", item.VTapID, md.LogPrefixes)
		}
		description := fmt.Sprintf("agent %s report process %s cmdline %s",
			vtapName, item.ProcessName, item.CommandLine)

		opts := []eventapi.TagFieldOption{eventapi.TagDescription(description)}

		switch t := item.DeviceType; t {
		case common.VIF_DEVICE_TYPE_POD:
			podID := item.DeviceID
			info, err := md.GetToolDataSet().GetPodInfoByID(podID)
			if err != nil {
				log.Error(err)
			} else {
				podGroupType, ok := md.GetToolDataSet().GetPodGroupTypeByID(info.PodGroupID)
				if !ok {
					log.Errorf("db pod_group type(id: %d) not found", info.PodGroupID, md.LogPrefixes)
				}

				opts = append(opts, []eventapi.TagFieldOption{
					eventapi.TagPodID(podID),
					eventapi.TagRegionID(info.RegionID),
					eventapi.TagAZID(info.AZID),
					eventapi.TagVPCID(info.VPCID),
					eventapi.TagPodClusterID(info.PodClusterID),
					eventapi.TagPodGroupID(info.PodGroupID),
					eventapi.TagPodGroupType(metadata.PodGroupTypeMap[podGroupType]),
					eventapi.TagPodNodeID(info.PodNodeID),
					eventapi.TagPodNSID(info.PodNamespaceID),
				}...)
				if l3DeviceOpts, ok := p.tool.getL3DeviceOptionsByPodNodeID(md, info.PodNodeID); ok {
					opts = append(opts, l3DeviceOpts...)
				}
			}

		case common.VIF_DEVICE_TYPE_POD_NODE:
			podNodeID := item.DeviceID
			info, err := md.GetToolDataSet().GetPodNodeInfoByID(podNodeID)
			if err != nil {
				log.Error(err)
			} else {
				opts = append(opts, []eventapi.TagFieldOption{
					eventapi.TagPodNodeID(podNodeID),
					eventapi.TagRegionID(info.RegionID),
					eventapi.TagAZID(info.AZID),
					eventapi.TagVPCID(info.VPCID),
					eventapi.TagPodClusterID(info.PodClusterID),
				}...)
				if l3DeviceOpts, ok := p.tool.getL3DeviceOptionsByPodNodeID(md, podNodeID); ok {
					opts = append(opts, l3DeviceOpts...)
				}
			}

		case common.VIF_DEVICE_TYPE_VM:
			vmID := item.DeviceID
			info, err := md.GetToolDataSet().GetVMInfoByID(vmID)
			if err != nil {
				log.Error(err)
			} else {
				opts = append(opts, []eventapi.TagFieldOption{
					eventapi.TagL3DeviceType(item.DeviceType),
					eventapi.TagL3DeviceID(vmID),
					eventapi.TagAZID(info.AZID),
					eventapi.TagRegionID(info.RegionID),
					eventapi.TagHostID(info.HostID),
					eventapi.TagVPCID(info.VPCID),
				}...)
			}
		default:
			log.Error("cannot support type: %s", t)
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagGProcessID(item.GID),
			eventapi.TagGProcessName(item.Name), // TODO @weiqiang why use name
		}...)

		p.createInstanceAndEnqueue(
			md,
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			p.deviceType,
			int(item.GID),
			opts...,
		)
	}
}

func (p *Process) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.Process) {
		opts := []eventapi.TagFieldOption{
			eventapi.TagGProcessID(item.GID),
			eventapi.TagGProcessName(item.Name),
		}
		// 当 pod 内的 container 重启并伴随进程删除时，pod 会关联上新的 container，
		// 而进程删除时无法使用其旧的 container 找到对应的 pod 信息，所以由 server 打 pod id。
		// 仅在 pod 内的进程删除时，才会打上 pod id， 并且其他 tag 还是由 ingester 打上。
		if item.DeviceType == common.VIF_DEVICE_TYPE_POD {
			opts = append(opts, eventapi.TagPodID(item.DeviceID))
		}
		p.createInstanceAndEnqueue(
			md,
			item.Lcuuid,
			eventapi.RESOURCE_EVENT_TYPE_DELETE,
			item.Name,
			p.deviceType,
			int(item.GID),
			opts...,
		)
	}
}
