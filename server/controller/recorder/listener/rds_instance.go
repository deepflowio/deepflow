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

package listener

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/event"
	"github.com/deepflowio/deepflow/server/libs/queue"
)

type RDSInstance struct {
	cache         *cache.Cache
	eventProducer *event.RDSInstance
}

func NewRDSInstance(c *cache.Cache, eq *queue.OverwriteQueue) *RDSInstance {
	lisener := &RDSInstance{
		cache:         c,
		eventProducer: event.NewRDSInstance(&c.ToolDataSet, eq),
	}
	return lisener
}

func (p *RDSInstance) OnUpdaterAdded(addedDBItems []*mysql.RDSInstance) {
	// p.cache.AddRDSInstances(addedDBItems)
	p.eventProducer.ProduceByAdd(addedDBItems)
}

func (p *RDSInstance) OnUpdaterUpdated(cloudItem *cloudmodel.RDSInstance, diffBase *cache.RDSInstance) {
	// diffBase.Update(cloudItem)
	// p.cache.UpdateRDSInstance(cloudItem)
}

func (p *RDSInstance) OnUpdaterDeleted(lcuuids []string) {
	p.eventProducer.ProduceByDelete(lcuuids)
	// p.cache.DeleteRDSInstances(lcuuids)
}
