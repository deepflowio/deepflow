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

// DHCPPort defines cache data structure.
type DHCPPort struct {
	lcuuid   string
	id       int
	name     string
	regionID int
	azID     int
	vpcID    int
}

func (t *DHCPPort) IsValid() bool {
	return t.lcuuid != ""
}

func (t *DHCPPort) Lcuuid() string {
	return t.lcuuid
}

func (t *DHCPPort) ID() int {
	return t.id
}

func (t *DHCPPort) Name() string {
	return t.name
}

func (t *DHCPPort) Region() int {
	return t.regionID
}

func (t *DHCPPort) AZ() int {
	return t.azID
}

func (t *DHCPPort) VPCID() int {
	return t.vpcID
}

func (t *DHCPPort) reset(dbItem *metadbmodel.DHCPPort, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.vpcID = dbItem.VPCID
}

func NewDHCPPortCollection(t *Tool) *DHCPPortCollection {
	c := new(DHCPPortCollection)
	c.collection = newCollectionBuilder[*DHCPPort]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_DHCP_PORT_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.DHCPPort { return new(metadbmodel.DHCPPort) }).
		withCacheItemFactory(func() *DHCPPort { return new(DHCPPort) }).
		build()
	return c
}

// DHCPPortCollection defines a collection that maps individual fields to the DHCPPort cache data structure.
type DHCPPortCollection struct {
	collection[*DHCPPort, *metadbmodel.DHCPPort]
}
