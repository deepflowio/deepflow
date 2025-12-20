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

// Network defines cache data structure.
type Network struct {
	lcuuid string
	id     int
	name   string
	vpcID  int
}

func (t *Network) IsValid() bool {
	return t.lcuuid != ""
}

func (t *Network) Lcuuid() string {
	return t.lcuuid
}

func (t *Network) ID() int {
	return t.id
}

func (t *Network) Name() string {
	return t.name
}

func (t *Network) VPCID() int {
	return t.vpcID
}

func (t *Network) reset(dbItem *metadbmodel.Network, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.vpcID = dbItem.VPCID
}

func NewNetworkCollection(t *Tool) *NetworkCollection {
	c := new(NetworkCollection)
	c.collection = newCollectionBuilder[*Network]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_NETWORK_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.Network { return new(metadbmodel.Network) }).
		withCacheItemFactory(func() *Network { return new(Network) }).
		build()
	return c
}

// NetworkCollection defines a collection that maps individual fields to the Network cache data structure.
type NetworkCollection struct {
	collection[*Network, *metadbmodel.Network]
}
