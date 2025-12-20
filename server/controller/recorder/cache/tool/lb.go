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

// LB defines cache data structure.
type LB struct {
	lcuuid   string
	id       int
	name     string
	regionID int
	vpcID    int
}

func (t *LB) IsValid() bool {
	return t.lcuuid != ""
}

func (t *LB) Lcuuid() string {
	return t.lcuuid
}

func (t *LB) ID() int {
	return t.id
}

func (t *LB) Name() string {
	return t.name
}

func (t *LB) RegionID() int {
	return t.regionID
}

func (t *LB) VPCID() int {
	return t.vpcID
}

func (t *LB) reset(dbItem *metadbmodel.LB, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.vpcID = dbItem.VPCID
}

func NewLBCollection(t *Tool) *LBCollection {
	c := new(LBCollection)
	c.collection = newCollectionBuilder[*LB]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_LB_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.LB { return new(metadbmodel.LB) }).
		withCacheItemFactory(func() *LB { return new(LB) }).
		build()
	return c
}

// LBCollection defines a collection that maps individual fields to the LB cache data structure.
type LBCollection struct {
	collection[*LB, *metadbmodel.LB]
}
