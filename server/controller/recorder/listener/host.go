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

type Host struct {
	cache         *cache.Cache
	eventProducer *event.Host
}

func NewHost(c *cache.Cache, eq *queue.OverwriteQueue) *Host {
	lisener := &Host{
		cache:         c,
		eventProducer: event.NewHost(&c.ToolDataSet, eq),
	}
	return lisener
}

func (p *Host) OnUpdaterAdded(addedDBItems []*mysql.Host) {
	// p.cache.AddHosts(addedDBItems)
	p.eventProducer.ProduceByAdd(addedDBItems)
}

func (p *Host) OnUpdaterUpdated(cloudItem *cloudmodel.Host, diffBase *cache.Host) {
	p.eventProducer.ProduceByUpdate(cloudItem, diffBase)
	// diffBase.Update(cloudItem)
	// p.cache.UpdateHost(cloudItem)
}

func (p *Host) OnUpdaterDeleted(lcuuids []string) {
	p.eventProducer.ProduceByDelete(lcuuids)
	// p.cache.DeleteHosts(lcuuids)
}
