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

type LANIP struct {
	ResourceBase
	SubDomainLcuuid string
}

func (a *LANIP) reset(dbItem *metadbmodel.LANIP, tool *tool.Tool) {
	a.SubDomainLcuuid = dbItem.SubDomain
}

func NewLANIPCollection(t *tool.Tool) *LANIPCollection {
	c := new(LANIPCollection)
	c.collection = newCollectionBuilder[*LANIP]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_LAN_IP_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.LANIP { return new(metadbmodel.LANIP) }).
		withCacheItemFactory(func() *LANIP { return new(LANIP) }).
		build()
	return c
}

type LANIPCollection struct {
	collection[*LANIP, *metadbmodel.LANIP]
}
