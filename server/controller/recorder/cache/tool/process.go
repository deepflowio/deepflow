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

// Process defines cache data structure.
type Process struct {
	lcuuid     string
	id         int
	name       string
	deviceType int
	deviceID   int
	podGroupID int
	podNodeID  int
	vmID       int
	vpcID      int
}

func (t *Process) IsValid() bool {
	return t.lcuuid != ""
}

func (t *Process) Lcuuid() string {
	return t.lcuuid
}

func (t *Process) ID() int {
	return t.id
}

func (t *Process) Name() string {
	return t.name
}

func (t *Process) DeviceType() int {
	return t.deviceType
}

func (t *Process) DeviceID() int {
	return t.deviceID
}

func (t *Process) PodGroupID() int {
	return t.podGroupID
}

func (t *Process) PodNodeID() int {
	return t.podNodeID
}

func (t *Process) VMID() int {
	return t.vmID
}

func (t *Process) VPCID() int {
	return t.vpcID
}

func (t *Process) reset(dbItem *metadbmodel.Process, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.deviceType = dbItem.DeviceType
	t.deviceID = dbItem.DeviceID
	t.podGroupID = dbItem.PodGroupID
	t.podNodeID = dbItem.PodNodeID
	t.vmID = dbItem.VMID
	t.vpcID = dbItem.VPCID
}

func NewProcessCollection(t *Tool) *ProcessCollection {
	c := new(ProcessCollection)
	c.resetExt()
	c.collection = newCollectionBuilder[*Process]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_PROCESS_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.Process { return new(metadbmodel.Process) }).
		withCacheItemFactory(func() *Process { return new(Process) }).
		withExtender(c).
		build()
	return c
}

// ProcessCollection defines a collection that maps individual fields to the Process cache data structure.
type ProcessCollection struct {
	collection[*Process, *metadbmodel.Process]
	ProcessCollectionExt
}
