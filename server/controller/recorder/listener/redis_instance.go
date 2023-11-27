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

type RedisInstance struct {
	cache         *cache.Cache
	eventProducer *event.RedisInstance
}

func NewRedisInstance(c *cache.Cache, eq *queue.OverwriteQueue) *RedisInstance {
	listener := &RedisInstance{
		cache:         c,
		eventProducer: event.NewRedisInstance(c.ToolDataSet, eq),
	}
	return listener
}

func (ri *RedisInstance) OnUpdaterAdded(addedDBItems []*mysql.RedisInstance) {
	ri.eventProducer.ProduceByAdd(addedDBItems)
	ri.cache.AddRedisInstances(addedDBItems)
}

func (ri *RedisInstance) OnUpdaterUpdated(cloudItem *cloudmodel.RedisInstance, diffBase *diffbase.RedisInstance) {
	diffBase.Update(cloudItem)
	ri.cache.UpdateRedisInstance(cloudItem)
}

func (ri *RedisInstance) OnUpdaterDeleted(lcuuids []string) {
	ri.eventProducer.ProduceByDelete(lcuuids)
	ri.cache.DeleteRedisInstances(lcuuids)
}
