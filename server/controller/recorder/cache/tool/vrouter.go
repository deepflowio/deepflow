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

// VRouter defines cache data structure.
type VRouter struct {
	lcuuid         string
	id             int
	name           string
	regionID       int
	vpcID          int
	gwLaunchServer string
}

func (t *VRouter) IsValid() bool {
	return t.lcuuid != ""
}

func (t *VRouter) Lcuuid() string {
	return t.lcuuid
}

func (t *VRouter) ID() int {
	return t.id
}

func (t *VRouter) Name() string {
	return t.name
}

func (t *VRouter) RegionID() int {
	return t.regionID
}

func (t *VRouter) VPCID() int {
	return t.vpcID
}

func (t *VRouter) GWLaunchServer() string {
	return t.gwLaunchServer
}

func (t *VRouter) reset(dbItem *metadbmodel.VRouter, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.vpcID = dbItem.VPCID
	t.gwLaunchServer = dbItem.GWLaunchServer
}

func NewVRouterCollection(t *Tool) *VRouterCollection {
	c := new(VRouterCollection)
	c.collection = newCollectionBuilder[*VRouter]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.VRouter { return new(metadbmodel.VRouter) }).
		withCacheItemFactory(func() *VRouter { return new(VRouter) }).
		build()
	return c
}

// VRouterCollection defines a collection that maps individual fields to the VRouter cache data structure.
type VRouterCollection struct {
	collection[*VRouter, *metadbmodel.VRouter]
}
