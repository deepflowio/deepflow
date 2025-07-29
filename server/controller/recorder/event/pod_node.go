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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/pubsub/message"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type PodNode struct {
	ManagerComponent
	CUDSubscriberComponent
	deviceType int
	tool       *IPTool
}

func NewPodNode(q *queue.OverwriteQueue) *PodNode {
	mng := &PodNode{
		newManagerComponent(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN, q),
		newCUDSubscriberComponent(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN),
		ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE,
		newTool(),
	}
	mng.SetSubscriberSelf(mng)
	return mng
}

func (p *PodNode) OnResourceBatchAdded(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.PodNode) {
		var opts []eventapi.TagFieldOption
		var domainLcuuid string
		info, err := md.GetToolDataSet().GetPodNodeInfoByID(item.ID)
		if err != nil {
			log.Error(err)
		} else {
			opts = append(opts, []eventapi.TagFieldOption{
				eventapi.TagAZID(info.AZID),
				eventapi.TagRegionID(info.RegionID),
			}...)
			domainLcuuid = info.DomainLcuuid
		}
		opts = append(opts, []eventapi.TagFieldOption{
			eventapi.TagPodNodeID(item.ID),
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagPodClusterID(item.PodClusterID),
		}...)

		l3DeviceOpts, ok := p.tool.getL3DeviceOptionsByPodNodeID(md, item.ID)
		if ok {
			opts = append(opts, l3DeviceOpts...)
			p.createInstanceAndEnqueue(md,
				item.Lcuuid,
				eventapi.RESOURCE_EVENT_TYPE_CREATE,
				item.Name,
				p.deviceType,
				item.ID,
				opts...,
			)
		} else {
			p.enqueueInstanceIfInsertIntoMetadbFailed(
				md,
				item.Lcuuid,
				domainLcuuid,
				eventapi.RESOURCE_EVENT_TYPE_CREATE,
				item.Name,
				p.deviceType,
				item.ID,
				opts...,
			)
		}
	}
}

func (p *PodNode) OnResourceBatchDeleted(md *message.Metadata, msg interface{}) {
	for _, item := range msg.([]*metadbmodel.PodNode) {
		p.createInstanceAndEnqueue(md, item.Lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, item.Name, p.deviceType, item.ID)
	}
}
