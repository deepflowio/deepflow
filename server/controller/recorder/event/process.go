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
		vtapItem := md.GetToolDataSet().Agent().GetById(int(item.VTapID))
		if !vtapItem.IsValid() {
			log.Errorf("vtap name not found for vtap id %d", item.VTapID, md.LogPrefixes)
		}
		vtapName := vtapItem.Name()
		description := fmt.Sprintf("agent %s report process %s cmdline %s",
			vtapName, item.ProcessName, item.CommandLine)

		opts := []eventapi.TagFieldOption{eventapi.TagDescription(description)}

		switch t := item.DeviceType; t {
		case common.VIF_DEVICE_TYPE_POD:
			podID := item.DeviceID
			podItem := md.GetToolDataSet().Pod().GetById(podID)
			if !podItem.IsValid() {
				log.Errorf("pod(id=%d) not found", podID, md.LogPrefixes)
			} else {
				pgItem := md.GetToolDataSet().PodGroup().GetById(podItem.PodGroupId())
				if !pgItem.IsValid() {
					log.Errorf("db pod_group type(id: %d) not found", podItem.PodGroupId(), md.LogPrefixes)
				}

				opts = append(opts, []eventapi.TagFieldOption{
					eventapi.TagPodID(podID),
					eventapi.TagRegionID(podItem.RegionId()),
					eventapi.TagAZID(podItem.AzId()),
					eventapi.TagVPCID(podItem.VpcId()),
					eventapi.TagPodClusterID(podItem.PodClusterId()),
					eventapi.TagPodGroupID(podItem.PodGroupId()),
					eventapi.TagPodGroupType(metadata.PodGroupTypeMap[pgItem.GType()]),
					eventapi.TagPodNodeID(podItem.PodNodeId()),
					eventapi.TagPodNSID(podItem.PodNamespaceId()),
				}...)
				if l3DeviceOpts, ok := p.tool.getL3DeviceOptionsByPodNodeID(md, podItem.PodNodeId()); ok {
					opts = append(opts, l3DeviceOpts...)
				}
			}

		case common.VIF_DEVICE_TYPE_POD_NODE:
			podNodeID := item.DeviceID
			pnItem := md.GetToolDataSet().PodNode().GetById(podNodeID)
			if !pnItem.IsValid() {
				log.Errorf("pod_node(id=%d) not found", podNodeID, md.LogPrefixes)
			} else {
				opts = append(opts, []eventapi.TagFieldOption{
					eventapi.TagPodNodeID(podNodeID),
					eventapi.TagRegionID(pnItem.RegionId()),
					eventapi.TagAZID(pnItem.AzId()),
					eventapi.TagVPCID(pnItem.VpcId()),
					eventapi.TagPodClusterID(pnItem.PodClusterId()),
				}...)
				if l3DeviceOpts, ok := p.tool.getL3DeviceOptionsByPodNodeID(md, podNodeID); ok {
					opts = append(opts, l3DeviceOpts...)
				}
			}

		case common.VIF_DEVICE_TYPE_VM:
			vmID := item.DeviceID
			vmItem := md.GetToolDataSet().Vm().GetById(vmID)
			if !vmItem.IsValid() {
				log.Errorf("vm(id=%d) not found", vmID, md.LogPrefixes)
			} else {
				opts = append(opts, []eventapi.TagFieldOption{
					eventapi.TagL3DeviceType(item.DeviceType),
					eventapi.TagL3DeviceID(vmID),
					eventapi.TagAZID(vmItem.AzId()),
					eventapi.TagRegionID(vmItem.RegionId()),
					eventapi.TagHostID(vmItem.HostId()),
					eventapi.TagVPCID(vmItem.VpcId()),
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
