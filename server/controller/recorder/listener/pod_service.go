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

type PodService struct {
	cache         *cache.Cache
	eventProducer *event.PodService
}

func NewPodService(c *cache.Cache, eq *queue.OverwriteQueue) *PodService {
	listener := &PodService{
		cache:         c,
		eventProducer: event.NewPodService(c.ToolDataSet, eq),
	}
	return listener
}

func (ps *PodService) OnUpdaterAdded(addedDBItems []*mysql.PodService) {
	ps.eventProducer.ProduceByAdd(addedDBItems)
	ps.cache.AddPodServices(addedDBItems)
}

func (ps *PodService) OnUpdaterUpdated(cloudItem *cloudmodel.PodService, diffBase *diffbase.PodService) {
	ps.eventProducer.ProduceByUpdate(cloudItem, diffBase)
	diffBase.Update(cloudItem)
	ps.cache.UpdatePodService(cloudItem)
}

func (ps *PodService) OnUpdaterDeleted(lcuuids []string) {
	ps.eventProducer.ProduceByDelete(lcuuids)
	ps.cache.DeletePodServices(lcuuids)
}
