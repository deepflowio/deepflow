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

type VRouter struct {
	ResourceBase
	Name         string
	Label        string
	VPCLcuuid    string
	RegionLcuuid string
}

func (a *VRouter) reset(dbItem *metadbmodel.VRouter, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.Label = dbItem.Label
	a.VPCLcuuid = tool.VPC().GetByID(dbItem.VPCID).Lcuuid()
	a.RegionLcuuid = dbItem.Region
}

func NewVRouterCollection(t *tool.Tool) *VRouterCollection {
	c := new(VRouterCollection)
	c.collection = newCollectionBuilder[*VRouter]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.VRouter { return new(metadbmodel.VRouter) }).
		withCacheItemFactory(func() *VRouter { return new(VRouter) }).
		build()
	return c
}

type VRouterCollection struct {
	collection[*VRouter, *metadbmodel.VRouter]
}
