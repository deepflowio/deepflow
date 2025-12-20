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

type VPC struct {
	ResourceBase
	Name         string
	Label        string
	TunnelID     int
	CIDR         string
	RegionLcuuid string
	Owner        string
}

func (a *VPC) reset(dbItem *metadbmodel.VPC, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.Label = dbItem.Label
	a.TunnelID = dbItem.TunnelID
	a.CIDR = dbItem.CIDR
	a.RegionLcuuid = dbItem.Region
	a.Owner = dbItem.Owner
}

func NewVPCCollection(t *tool.Tool) *VPCCollection {
	c := new(VPCCollection)
	c.collection = newCollectionBuilder[*VPC]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_VPC_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.VPC { return new(metadbmodel.VPC) }).
		withCacheItemFactory(func() *VPC { return new(VPC) }).
		build()
	return c
}

type VPCCollection struct {
	collection[*VPC, *metadbmodel.VPC]
}
