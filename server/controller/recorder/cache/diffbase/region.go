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

type Region struct {
	ResourceBase
	Name  string
	Label string
}

func (a *Region) reset(dbItem *metadbmodel.Region, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.Label = dbItem.Label
}

func NewRegionCollection(t *tool.Tool) *RegionCollection {
	c := new(RegionCollection)
	c.collection = newCollectionBuilder[*Region]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_REGION_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.Region { return new(metadbmodel.Region) }).
		withCacheItemFactory(func() *Region { return new(Region) }).
		build()
	return c
}

type RegionCollection struct {
	collection[*Region, *metadbmodel.Region]
}
