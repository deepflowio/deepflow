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

type VRouter struct {
	EventManager[cloudmodel.VRouter, mysql.VRouter, *cache.VRouter]
	deviceType int
}

func NewVRouter(toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *VRouter {
	mng := &VRouter{
		EventManager[cloudmodel.VRouter, mysql.VRouter, *cache.VRouter]{
			resourceType: RESOURCE_TYPE_VROUTER_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		common.VIF_DEVICE_TYPE_VROUTER,
	}
	return mng
}

func (r *VRouter) ProduceByAdd(items []*mysql.VRouter) {
	for _, item := range items {
		r.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_CREATE, r.deviceType, item.ID, item.Name, "", []uint32{}, []string{})
	}
}

func (r *VRouter) ProduceByUpdate(cloudItem *cloudmodel.VRouter, diffBase *cache.VRouter) {
}

func (r *VRouter) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := r.ToolDataSet.GetVRouterIDByLcuuid(lcuuid)
		if ok {
			name, ok = r.ToolDataSet.GetVRouterNameByID(id)
			if !ok {
				log.Error(idByLcuuidNotFound(r.resourceType, lcuuid))
			}
		} else {
			log.Error(nameByIDNotFound(r.resourceType, id))
		}

		r.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_DELETE, r.deviceType, id, name, "", []uint32{}, []string{})
	}
}
