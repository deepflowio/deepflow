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

// VPC defines cache data structure.
type VPC struct {
	lcuuid string
	id     int
}

func (t *VPC) IsValid() bool {
	return t.lcuuid != ""
}

func (t *VPC) Lcuuid() string {
	return t.lcuuid
}

func (t *VPC) ID() int {
	return t.id
}

func (t *VPC) reset(dbItem *metadbmodel.VPC, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
}

func NewVPCCollection(t *Tool) *VPCCollection {
	c := new(VPCCollection)
	c.collection = newCollectionBuilder[*VPC]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_VPC_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.VPC { return new(metadbmodel.VPC) }).
		withCacheItemFactory(func() *VPC { return new(VPC) }).
		build()
	return c
}

// VPCCollection defines a collection that maps individual fields to the VPC cache data structure.
type VPCCollection struct {
	collection[*VPC, *metadbmodel.VPC]
}
