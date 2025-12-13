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

// VMPodNodeConnection defines cache data structure.
type VMPodNodeConnection struct {
	lcuuid    string
	id        int
	vmID      int
	podNodeID int
}

func (t *VMPodNodeConnection) IsValid() bool {
	return t.lcuuid != ""
}

func (t *VMPodNodeConnection) Lcuuid() string {
	return t.lcuuid
}

func (t *VMPodNodeConnection) ID() int {
	return t.id
}

func (t *VMPodNodeConnection) VMID() int {
	return t.vmID
}

func (t *VMPodNodeConnection) PodNodeID() int {
	return t.podNodeID
}

func (t *VMPodNodeConnection) reset(dbItem *metadbmodel.VMPodNodeConnection, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.vmID = dbItem.VMID
	t.podNodeID = dbItem.PodNodeID
}

func NewVMPodNodeConnectionCollection(t *Tool) *VMPodNodeConnectionCollection {
	c := new(VMPodNodeConnectionCollection)
	c.collection = newCollectionBuilder[*VMPodNodeConnection]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.VMPodNodeConnection { return new(metadbmodel.VMPodNodeConnection) }).
		withCacheItemFactory(func() *VMPodNodeConnection { return new(VMPodNodeConnection) }).
		build()
	return c
}

// VMPodNodeConnectionCollection defines a collection that maps individual fields to the VMPodNodeConnection cache data structure.
type VMPodNodeConnectionCollection struct {
	collection[*VMPodNodeConnection, *metadbmodel.VMPodNodeConnection]
}
