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
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	. "github.com/deepflowys/deepflow/server/controller/recorder/common"
	"github.com/deepflowys/deepflow/server/libs/eventapi"
	"github.com/deepflowys/deepflow/server/libs/queue"
)

type Pod struct {
	EventManager[cloudmodel.IP, mysql.Pod, *cache.Pod]
}

func NewPod(toolDS cache.ToolDataSet, eq *queue.OverwriteQueue) *Pod {
	mng := &Pod{
		EventManager[cloudmodel.IP, mysql.Pod, *cache.Pod]{
			resourceType: RESOURCE_TYPE_POD_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
	}
	return mng
}

func (p *Pod) ProduceByAdd(items []*mysql.Pod) {
	for _, item := range items {
		p.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_CREATE, common.VIF_DEVICE_TYPE_POD, item.ID, item.Name, "")
	}
}

func (p *Pod) ProduceByUpdate(cloudItem *cloudmodel.Pod, diffBase *cache.Pod) {
	if diffBase.CreatedAt != cloudItem.CreatedAt {
		var id int
		var name string
		id, ok := p.ToolDataSet.GetPodIDByLcuuid(diffBase.Lcuuid)
		if ok {
			name, ok = p.ToolDataSet.GetPodNameByID(id)
			if !ok {
				log.Error(idByLcuuidNotFound(p.resourceType, diffBase.Lcuuid))
			}
		} else {
			log.Error(nameByIDNotFound(p.resourceType, id))
		}

		var oldPodNodeName string
		oldPodNodeID, ok := p.ToolDataSet.GetPodNodeIDByLcuuid(diffBase.PodNodeLcuuid)
		if ok {
			oldPodNodeName, ok = p.ToolDataSet.GetPodNodeNameByID(oldPodNodeID)
			if !ok {
				log.Error(nameByIDNotFound(RESOURCE_TYPE_POD_NODE_EN, id))
			}
		} else {
			log.Error(idByLcuuidNotFound(RESOURCE_TYPE_POD_NODE_EN, diffBase.PodNodeLcuuid))
		}

		var newPodNodeName string
		newPodNodeID, ok := p.ToolDataSet.GetPodNodeIDByLcuuid(cloudItem.PodNodeLcuuid)
		if ok {
			newPodNodeName, ok = p.ToolDataSet.GetPodNodeNameByID(newPodNodeID)
			if !ok {
				log.Error(nameByIDNotFound(RESOURCE_TYPE_POD_NODE_EN, id))
			}
		} else {
			log.Error(idByLcuuidNotFound(RESOURCE_TYPE_POD_NODE_EN, diffBase.PodNodeLcuuid))
		}

		p.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_RECREATE, common.VIF_DEVICE_TYPE_POD, id, name, fmt.Sprintf("%s,%s", oldPodNodeName, newPodNodeName))
	}
}

func (p *Pod) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := p.ToolDataSet.GetPodIDByLcuuid(lcuuid)
		if ok {
			name, ok = p.ToolDataSet.GetPodNameByID(id)
			if !ok {
				log.Error(idByLcuuidNotFound(p.resourceType, lcuuid))
			}
		} else {
			log.Error(nameByIDNotFound(p.resourceType, id))
		}

		p.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_DELETE, common.VIF_DEVICE_TYPE_POD, id, name, "")
	}
}
