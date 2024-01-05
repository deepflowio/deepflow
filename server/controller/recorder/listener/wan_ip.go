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

type WANIP struct {
	cache         *cache.Cache
	eventProducer *event.WANIP
}

func NewWANIP(c *cache.Cache, eq *queue.OverwriteQueue) *WANIP {
	listener := &WANIP{
		cache:         c,
		eventProducer: event.NewWANIP(c.ToolDataSet, eq),
	}
	return listener
}

func (i *WANIP) OnUpdaterAdded(addedDBItems []*mysql.WANIP) {
	i.eventProducer.ProduceByAdd(addedDBItems)
	i.cache.AddWANIPs(addedDBItems)
}

func (i *WANIP) OnUpdaterUpdated(cloudItem *cloudmodel.IP, diffBase *diffbase.WANIP) {
	i.eventProducer.ProduceByUpdate(cloudItem, diffBase)
	diffBase.Update(cloudItem)
}

func (i *WANIP) OnUpdaterDeleted(lcuuids []string) {
	i.eventProducer.ProduceByDelete(lcuuids)
	i.cache.DeleteWANIPs(lcuuids)
}
