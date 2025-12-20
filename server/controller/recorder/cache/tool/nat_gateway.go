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

// NATGateway defines cache data structure.
type NATGateway struct {
	lcuuid   string
	id       int
	name     string
	regionID int
	azID     int
	vpcID    int
}

func (t *NATGateway) IsValid() bool {
	return t.lcuuid != ""
}

func (t *NATGateway) Lcuuid() string {
	return t.lcuuid
}

func (t *NATGateway) ID() int {
	return t.id
}

func (t *NATGateway) Name() string {
	return t.name
}

func (t *NATGateway) RegionID() int {
	return t.regionID
}

func (t *NATGateway) AZID() int {
	return t.azID
}

func (t *NATGateway) VPCID() int {
	return t.vpcID
}

func (t *NATGateway) reset(dbItem *metadbmodel.NATGateway, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.vpcID = dbItem.VPCID
}

func NewNATGatewayCollection(t *Tool) *NATGatewayCollection {
	c := new(NATGatewayCollection)
	c.collection = newCollectionBuilder[*NATGateway]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.NATGateway { return new(metadbmodel.NATGateway) }).
		withCacheItemFactory(func() *NATGateway { return new(NATGateway) }).
		build()
	return c
}

// NATGatewayCollection defines a collection that maps individual fields to the NATGateway cache data structure.
type NATGatewayCollection struct {
	collection[*NATGateway, *metadbmodel.NATGateway]
}
