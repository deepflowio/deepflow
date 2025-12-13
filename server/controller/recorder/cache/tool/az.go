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

// AZ defines cache data structure.
type AZ struct {
	lcuuid string
	id     int
	name   string
}

func (t *AZ) IsValid() bool {
	return t.lcuuid != ""
}

func (t *AZ) Lcuuid() string {
	return t.lcuuid
}

func (t *AZ) ID() int {
	return t.id
}

func (t *AZ) Name() string {
	return t.name
}

func (t *AZ) reset(dbItem *metadbmodel.AZ, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
}

func NewAZCollection(t *Tool) *AZCollection {
	c := new(AZCollection)
	c.collection = newCollectionBuilder[*AZ]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_AZ_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.AZ { return new(metadbmodel.AZ) }).
		withCacheItemFactory(func() *AZ { return new(AZ) }).
		build()
	return c
}

// AZCollection defines a collection that maps individual fields to the AZ cache data structure.
type AZCollection struct {
	collection[*AZ, *metadbmodel.AZ]
}
