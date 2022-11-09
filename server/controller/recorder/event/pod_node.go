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
	cloudmodel "github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	. "github.com/deepflowys/deepflow/server/controller/recorder/common"
	"github.com/deepflowys/deepflow/server/libs/eventapi"
	"github.com/deepflowys/deepflow/server/libs/queue"
)

type PodNode struct {
	EventManager[cloudmodel.PodNode, mysql.PodNode, *cache.PodNode]
	deviceType int
}

func NewPodNode(toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *PodNode {
	mng := &PodNode{
		EventManager[cloudmodel.PodNode, mysql.PodNode, *cache.PodNode]{
			resourceType: RESOURCE_TYPE_POD_NODE_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		common.VIF_DEVICE_TYPE_POD_NODE,
	}
	return mng
}

func (p *PodNode) ProduceByAdd(items []*mysql.PodNode) {
	for _, item := range items {
		regionID, azID, err := getRegionIDAndAZIDByLcuuid(p.ToolDataSet, item.Region, item.AZ)
		if err != nil {
			log.Error(err)
		}

		p.createAndPutEvent(
			eventapi.RESOURCE_EVENT_TYPE_CREATE,
			item.Name,
			p.deviceType,
			item.ID,
			eventapi.TagPodNodeID(item.ID),
			eventapi.TagRegionID(regionID),
			eventapi.TagAZID(azID),
			eventapi.TagVPCID(item.VPCID),
			eventapi.TagPodNodeID(item.ID),
			eventapi.TagPodClusterID(item.PodClusterID),
		)
	}
}

func (p *PodNode) ProduceByUpdate(cloudItem *cloudmodel.PodNode, diffBase *cache.PodNode) {
}

func (p *PodNode) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := p.ToolDataSet.GetPodNodeIDByLcuuid(lcuuid)
		if ok {
			name, ok = p.ToolDataSet.GetPodNodeNameByID(id)
			if !ok {
				log.Error(idByLcuuidNotFound(p.resourceType, lcuuid))
			}
		} else {
			log.Error(nameByIDNotFound(p.resourceType, id))
		}

		p.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_DELETE, name, p.deviceType, id)
	}
}
