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

type WANIP struct {
	ResourceBase
	RegionLcuuid    string
	SubDomainLcuuid string
}

func (a *WANIP) reset(dbItem *metadbmodel.WANIP, tool *tool.Tool) {
	a.RegionLcuuid = dbItem.Region
	a.SubDomainLcuuid = dbItem.SubDomain
}

func NewWANIPCollection(t *tool.Tool) *WANIPCollection {
	c := new(WANIPCollection)
	c.collection = newCollectionBuilder[*WANIP]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_WAN_IP_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.WANIP { return new(metadbmodel.WANIP) }).
		withCacheItemFactory(func() *WANIP { return new(WANIP) }).
		build()
	return c
}

type WANIPCollection struct {
	collection[*WANIP, *metadbmodel.WANIP]
}
