/*
 * Copyright (c) 2023 Yunshan Networks
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
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type PodNode struct {
	EventManagerBase
	deviceType int
}

func NewPodNode(toolDS *tool.DataSet, eq *queue.OverwriteQueue) *PodNode {
	mng := &PodNode{
		EventManagerBase{
			resourceType: ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		ctrlrcommon.VIF_DEVICE_TYPE_POD_NODE,
	}
	return mng
}

func (p *PodNode) ProduceByAdd(items []*mysql.PodNode) {
	for _, item := range items {
		var opts []eventapi.TagFieldOption
		var domainLcuuid string
		info, err := p.ToolDataSet.GetPodNodeInfoByID(item.ID)
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

		l3DeviceOpts, ok := getL3DeviceOptionsByPodNodeID(p.ToolDataSet, item.ID)
		if ok {
			opts = append(opts, l3DeviceOpts...)
			p.createAndEnqueue(
				item.Lcuuid,
				eventapi.RESOURCE_EVENT_TYPE_CREATE,
				item.Name,
				p.deviceType,
				item.ID,
				opts...,
			)
		} else {
			p.enqueueIfInsertIntoMySQLFailed(
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

func (p *PodNode) ProduceByUpdate(cloudItem *cloudmodel.PodNode, diffBase *diffbase.PodNode) {
}

func (p *PodNode) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var name string
		id := p.ToolDataSet.GetPodNodeIDByLcuuid(lcuuid)
		if id != 0 {
			var err error
			name, err = p.ToolDataSet.GetPodNodeNameByID(id)
			if err != nil {
				log.Errorf("%v, %v", idByLcuuidNotFound(p.resourceType, lcuuid), err)
			}
		}

		p.createAndEnqueue(lcuuid, eventapi.RESOURCE_EVENT_TYPE_DELETE, name, p.deviceType, id)
	}
}
