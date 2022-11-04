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

type PodService struct {
	EventManager[cloudmodel.PodService, mysql.PodService, *cache.PodService]
	deviceType int
}

func NewPodService(toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *PodService {
	mng := &PodService{
		EventManager[cloudmodel.PodService, mysql.PodService, *cache.PodService]{
			resourceType: RESOURCE_TYPE_POD_SERVICE_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		common.VIF_DEVICE_TYPE_POD_SERVICE,
	}
	return mng
}

func (p *PodService) ProduceByAdd(items []*mysql.PodService) {
	for _, item := range items {
		p.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_CREATE, p.deviceType, item.ID, item.Name, "", []uint32{}, []string{})
	}
}

func (p *PodService) ProduceByUpdate(cloudItem *cloudmodel.PodService, diffBase *cache.PodService) {
}

func (p *PodService) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := p.ToolDataSet.GetPodServiceIDByLcuuid(lcuuid)
		if ok {
			name, ok = p.ToolDataSet.GetPodServiceNameByID(id)
			if !ok {
				log.Error(idByLcuuidNotFound(p.resourceType, lcuuid))
			}
		} else {
			log.Error(nameByIDNotFound(p.resourceType, id))
		}

		p.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_DELETE, p.deviceType, id, name, "", []uint32{}, []string{})
	}
}
