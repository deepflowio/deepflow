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

type RedisInstance struct {
	EventManager[cloudmodel.RedisInstance, mysql.RedisInstance, *cache.RedisInstance]
	deviceType int
}

func NewRedisInstance(toolDS *cache.ToolDataSet, eq *queue.OverwriteQueue) *RedisInstance {
	mng := &RedisInstance{
		EventManager[cloudmodel.RedisInstance, mysql.RedisInstance, *cache.RedisInstance]{
			resourceType: RESOURCE_TYPE_REDIS_INSTANCE_EN,
			ToolDataSet:  toolDS,
			Queue:        eq,
		},
		common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
	}
	return mng
}

func (r *RedisInstance) ProduceByAdd(items []*mysql.RedisInstance) {
	for _, item := range items {
		r.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_CREATE, item.Name, r.deviceType, item.ID)
	}
}

func (r *RedisInstance) ProduceByUpdate(cloudItem *cloudmodel.RedisInstance, diffBase *cache.RedisInstance) {
}

func (r *RedisInstance) ProduceByDelete(lcuuids []string) {
	for _, lcuuid := range lcuuids {
		var id int
		var name string
		id, ok := r.ToolDataSet.GetRedisInstanceIDByLcuuid(lcuuid)
		if ok {
			name, ok = r.ToolDataSet.GetRedisInstanceNameByID(id)
			if !ok {
				log.Error(idByLcuuidNotFound(r.resourceType, lcuuid))
			}
		} else {
			log.Error(nameByIDNotFound(r.resourceType, id))
		}

		r.createAndPutEvent(eventapi.RESOURCE_EVENT_TYPE_DELETE, name, r.deviceType, id)
	}
}
