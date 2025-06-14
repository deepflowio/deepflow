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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/event"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type PodGroupConfigMapConnection struct {
	cache         *cache.Cache
	eventProducer *event.PodGroupConfigMapConnection
}

func NewPodGroupConfigMapConnection(c *cache.Cache, eq *queue.OverwriteQueue) *PodGroupConfigMapConnection {
	listener := &PodGroupConfigMapConnection{
		cache:         c,
		eventProducer: event.NewPodGroupConfigMapConnection(c.ToolDataSet, eq),
	}
	return listener
}

func (h *PodGroupConfigMapConnection) OnUpdaterAdded(addedDBItems []*mysqlmodel.PodGroupConfigMapConnection) {
	h.eventProducer.ProduceByAdd(addedDBItems)
	h.cache.AddPodGroupConfigMapConnections(addedDBItems)
}

func (h *PodGroupConfigMapConnection) OnUpdaterUpdated(cloudItem *cloudmodel.PodGroupConfigMapConnection, diffBase *diffbase.PodGroupConfigMapConnection) {
}

func (h *PodGroupConfigMapConnection) OnUpdaterDeleted(lcuuids []string, deletedDBItems []*mysqlmodel.PodGroupConfigMapConnection) {
	h.cache.DeletePodGroupConfigMapConnections(lcuuids)
}
