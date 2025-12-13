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

// RDSInstance defines cache data structure.
type RDSInstance struct {
	lcuuid   string
	id       int
	name     string
	regionID int
	azID     int
	vpcID    int
}

func (t *RDSInstance) IsValid() bool {
	return t.lcuuid != ""
}

func (t *RDSInstance) Lcuuid() string {
	return t.lcuuid
}

func (t *RDSInstance) ID() int {
	return t.id
}

func (t *RDSInstance) Name() string {
	return t.name
}

func (t *RDSInstance) RegionID() int {
	return t.regionID
}

func (t *RDSInstance) AZID() int {
	return t.azID
}

func (t *RDSInstance) VPCID() int {
	return t.vpcID
}

func (t *RDSInstance) reset(dbItem *metadbmodel.RDSInstance, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.vpcID = dbItem.VPCID
}

func NewRDSInstanceCollection(t *Tool) *RDSInstanceCollection {
	c := new(RDSInstanceCollection)
	c.collection = newCollectionBuilder[*RDSInstance]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_RDS_INSTANCE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.RDSInstance { return new(metadbmodel.RDSInstance) }).
		withCacheItemFactory(func() *RDSInstance { return new(RDSInstance) }).
		build()
	return c
}

// RDSInstanceCollection defines a collection that maps individual fields to the RDSInstance cache data structure.
type RDSInstanceCollection struct {
	collection[*RDSInstance, *metadbmodel.RDSInstance]
}
