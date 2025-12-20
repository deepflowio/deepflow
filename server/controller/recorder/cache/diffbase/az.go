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

type AZ struct {
	ResourceBase
	Name         string
	Label        string
	RegionLcuuid string
}

func (a *AZ) reset(dbItem *metadbmodel.AZ, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.Label = dbItem.Label
	a.RegionLcuuid = dbItem.Region
}

func NewAZCollection(t *tool.Tool) *AZCollection {
	c := new(AZCollection)
	c.collection = newCollectionBuilder[*AZ]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_AZ_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.AZ { return new(metadbmodel.AZ) }).
		withCacheItemFactory(func() *AZ { return new(AZ) }).
		build()
	return c
}

type AZCollection struct {
	collection[*AZ, *metadbmodel.AZ]
}
