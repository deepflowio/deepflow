/*
 * Copyright (c) 2023 Yunshan Networks
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

type NATGateway struct {
	cache         *cache.Cache
	eventProducer *event.NATGateway
}

func NewNATGateway(c *cache.Cache, eq *queue.OverwriteQueue) *NATGateway {
	listener := &NATGateway{
		cache:         c,
		eventProducer: event.NewNATGateway(c.ToolDataSet, eq),
	}
	return listener
}

func (g *NATGateway) OnUpdaterAdded(addedDBItems []*mysql.NATGateway) {
	g.eventProducer.ProduceByAdd(addedDBItems)
	g.cache.AddNATGateways(addedDBItems)
}

func (g *NATGateway) OnUpdaterUpdated(cloudItem *cloudmodel.NATGateway, diffBase *diffbase.NATGateway) {
	g.eventProducer.ProduceByUpdate(cloudItem, diffBase)
	diffBase.Update(cloudItem)
	g.cache.UpdateNATGateway(cloudItem)
}

func (g *NATGateway) OnUpdaterDeleted(lcuuids []string) {
	g.eventProducer.ProduceByDelete(lcuuids)
	g.cache.DeleteNATGateways(lcuuids)
}
