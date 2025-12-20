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

// Subnet defines cache data structure.
type Subnet struct {
	lcuuid    string
	id        int
	name      string
	networkID int
}

func (t *Subnet) IsValid() bool {
	return t.lcuuid != ""
}

func (t *Subnet) Lcuuid() string {
	return t.lcuuid
}

func (t *Subnet) ID() int {
	return t.id
}

func (t *Subnet) Name() string {
	return t.name
}

func (t *Subnet) NetworkID() int {
	return t.networkID
}

func (t *Subnet) reset(dbItem *metadbmodel.Subnet, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.networkID = dbItem.NetworkID
}

func NewSubnetCollection(t *Tool) *SubnetCollection {
	c := new(SubnetCollection)
	c.collection = newCollectionBuilder[*Subnet]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_SUBNET_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.Subnet { return new(metadbmodel.Subnet) }).
		withCacheItemFactory(func() *Subnet { return new(Subnet) }).
		build()
	return c
}

// SubnetCollection defines a collection that maps individual fields to the Subnet cache data structure.
type SubnetCollection struct {
	collection[*Subnet, *metadbmodel.Subnet]
}
