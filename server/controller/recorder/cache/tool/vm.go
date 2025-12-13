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

// VM defines cache data structure.
type VM struct {
	lcuuid    string
	id        int
	name      string
	regionID  int
	azID      int
	vpcID     int
	hostID    int
	networkID int
	podNodeID int
}

func (t *VM) IsValid() bool {
	return t.lcuuid != ""
}

func (t *VM) Lcuuid() string {
	return t.lcuuid
}

func (t *VM) ID() int {
	return t.id
}

func (t *VM) Name() string {
	return t.name
}

func (t *VM) RegionID() int {
	return t.regionID
}

func (t *VM) AZID() int {
	return t.azID
}

func (t *VM) VPCID() int {
	return t.vpcID
}

func (t *VM) HostID() int {
	return t.hostID
}

func (t *VM) NetworkID() int {
	return t.networkID
}

func (t *VM) PodNodeID() int {
	return t.podNodeID
}

func (t *VM) SetPodNodeID(podNodeID int) {
	t.podNodeID = podNodeID
}

func (t *VM) reset(dbItem *metadbmodel.VM, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.vpcID = dbItem.VPCID
	t.hostID = dbItem.HostID
	t.networkID = dbItem.NetworkID
}

func NewVMCollection(t *Tool) *VMCollection {
	c := new(VMCollection)
	c.collection = newCollectionBuilder[*VM]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_VM_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.VM { return new(metadbmodel.VM) }).
		withCacheItemFactory(func() *VM { return new(VM) }).
		build()
	return c
}

// VMCollection defines a collection that maps individual fields to the VM cache data structure.
type VMCollection struct {
	collection[*VM, *metadbmodel.VM]
}
