/*
 * Copyright (c) 2024 Yunshan PodGroups
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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/event"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type PodGroup struct {
	cache         *cache.Cache
	eventProducer *event.PodGroup
}

func NewPodGroup(c *cache.Cache, eq *queue.OverwriteQueue) *PodGroup {
	listener := &PodGroup{
		cache:         c,
		eventProducer: event.NewPodGroup(c.ToolDataSet, eq),
	}
	return listener
}

func (p *PodGroup) OnUpdaterAdded(addedDBItems []*mysqlmodel.PodGroup) {
	p.cache.AddPodGroups(addedDBItems)
}

func (p *PodGroup) OnUpdaterUpdated(cloudItem *cloudmodel.PodGroup, diffBase *diffbase.PodGroup) {
	p.eventProducer.ProduceByUpdate(cloudItem, diffBase)
	diffBase.Update(cloudItem, p.cache.ToolDataSet)
}

func (p *PodGroup) OnUpdaterDeleted(lcuuids []string, deletedDBItems []*mysqlmodel.PodGroup) {
	p.cache.DeletePodGroups(lcuuids)
}
