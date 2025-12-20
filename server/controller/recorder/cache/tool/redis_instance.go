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

package tool

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

// RedisInstance defines cache data structure.
type RedisInstance struct {
	lcuuid   string
	id       int
	name     string
	regionID int
	azID     int
	vpcID    int
}

func (t *RedisInstance) IsValid() bool {
	return t.lcuuid != ""
}

func (t *RedisInstance) Lcuuid() string {
	return t.lcuuid
}

func (t *RedisInstance) ID() int {
	return t.id
}

func (t *RedisInstance) Name() string {
	return t.name
}

func (t *RedisInstance) RegionID() int {
	return t.regionID
}

func (t *RedisInstance) AZID() int {
	return t.azID
}

func (t *RedisInstance) VPCID() int {
	return t.vpcID
}

func (t *RedisInstance) reset(dbItem *metadbmodel.RedisInstance, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.vpcID = dbItem.VPCID
}

func NewRedisInstanceCollection(t *Tool) *RedisInstanceCollection {
	c := new(RedisInstanceCollection)
	c.collection = newCollectionBuilder[*RedisInstance]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.RedisInstance { return new(metadbmodel.RedisInstance) }).
		withCacheItemFactory(func() *RedisInstance { return new(RedisInstance) }).
		build()
	return c
}

// RedisInstanceCollection defines a collection that maps individual fields to the RedisInstance cache data structure.
type RedisInstanceCollection struct {
	collection[*RedisInstance, *metadbmodel.RedisInstance]
}
