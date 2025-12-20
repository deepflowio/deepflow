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

type FloatingIP struct {
	ResourceBase
	RegionLcuuid string
	VPCLcuuid    string
}

func (a *FloatingIP) reset(dbItem *metadbmodel.FloatingIP, tool *tool.Tool) {
	a.RegionLcuuid = dbItem.Region
	a.VPCLcuuid = tool.VPC().GetByID(dbItem.VPCID).Lcuuid()
}

func NewFloatingIPCollection(t *tool.Tool) *FloatingIPCollection {
	c := new(FloatingIPCollection)
	c.collection = newCollectionBuilder[*FloatingIP]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_FLOATING_IP_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.FloatingIP { return new(metadbmodel.FloatingIP) }).
		withCacheItemFactory(func() *FloatingIP { return new(FloatingIP) }).
		build()
	return c
}

type FloatingIPCollection struct {
	collection[*FloatingIP, *metadbmodel.FloatingIP]
}
