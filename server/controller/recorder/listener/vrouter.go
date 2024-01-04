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

package listener

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/event"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type VRouter struct {
	cache         *cache.Cache
	eventProducer *event.VRouter
}

func NewVRouter(c *cache.Cache, eq *queue.OverwriteQueue) *VRouter {
	listener := &VRouter{
		cache:         c,
		eventProducer: event.NewVRouter(c.ToolDataSet, eq),
	}
	return listener
}

func (r *VRouter) OnUpdaterAdded(addedDBItems []*mysql.VRouter) {
	r.eventProducer.ProduceByAdd(addedDBItems)
	r.cache.AddVRouters(addedDBItems)
}

func (r *VRouter) OnUpdaterUpdated(cloudItem *cloudmodel.VRouter, diffBase *diffbase.VRouter) {
	r.eventProducer.ProduceByUpdate(cloudItem, diffBase)
	diffBase.Update(cloudItem)
	r.cache.UpdateVRouter(cloudItem)
}

func (r *VRouter) OnUpdaterDeleted(lcuuids []string) {
	r.eventProducer.ProduceByDelete(lcuuids)
	r.cache.DeleteVRouters(lcuuids)
}
