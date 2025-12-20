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

type RoutingTable struct {
	ResourceBase
	Destination string
	Nexthop     string
	NexthopType string
}

func (a *RoutingTable) reset(dbItem *metadbmodel.RoutingTable, tool *tool.Tool) {
	a.Destination = dbItem.Destination
	a.Nexthop = dbItem.Nexthop
	a.NexthopType = dbItem.NexthopType
}

func NewRoutingTableCollection(t *tool.Tool) *RoutingTableCollection {
	c := new(RoutingTableCollection)
	c.collection = newCollectionBuilder[*RoutingTable]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_ROUTING_TABLE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.RoutingTable { return new(metadbmodel.RoutingTable) }).
		withCacheItemFactory(func() *RoutingTable { return new(RoutingTable) }).
		build()
	return c
}

type RoutingTableCollection struct {
	collection[*RoutingTable, *metadbmodel.RoutingTable]
}
