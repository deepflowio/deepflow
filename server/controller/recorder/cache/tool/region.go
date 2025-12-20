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

// Region defines cache data structure.
type Region struct {
	lcuuid string
	id     int
}

func (t *Region) IsValid() bool {
	return t.lcuuid != ""
}

func (t *Region) Lcuuid() string {
	return t.lcuuid
}

func (t *Region) ID() int {
	return t.id
}

func (t *Region) reset(dbItem *metadbmodel.Region, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
}

func NewRegionCollection(t *Tool) *RegionCollection {
	c := new(RegionCollection)
	c.collection = newCollectionBuilder[*Region]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_REGION_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.Region { return new(metadbmodel.Region) }).
		withCacheItemFactory(func() *Region { return new(Region) }).
		build()
	return c
}

// RegionCollection defines a collection that maps individual fields to the Region cache data structure.
type RegionCollection struct {
	collection[*Region, *metadbmodel.Region]
}
