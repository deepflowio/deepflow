/**
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

package diffbase

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

type RedisInstance struct {
	ResourceBase
	Name         string
	State        int
	PublicHost   string
	RegionLcuuid string
	AZLcuuid     string
}

func (a *RedisInstance) reset(dbItem *metadbmodel.RedisInstance, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.State = dbItem.State
	a.PublicHost = dbItem.PublicHost
	a.RegionLcuuid = dbItem.Region
	a.AZLcuuid = dbItem.AZ
}

func NewRedisInstanceCollection(t *tool.Tool) *RedisInstanceCollection {
	c := new(RedisInstanceCollection)
	c.collection = newCollectionBuilder[*RedisInstance]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.RedisInstance { return new(metadbmodel.RedisInstance) }).
		withCacheItemFactory(func() *RedisInstance { return new(RedisInstance) }).
		build()
	return c
}

type RedisInstanceCollection struct {
	collection[*RedisInstance, *metadbmodel.RedisInstance]
}
