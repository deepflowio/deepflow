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

// PodNode defines cache data structure.
type PodNode struct {
	lcuuid       string
	id           int
	domainLcuuid string
	name         string
	regionID     int
	azID         int
	vpcID        int
	podClusterID int
	vmID         int
}

func (t *PodNode) IsValid() bool {
	return t.lcuuid != ""
}

func (t *PodNode) Lcuuid() string {
	return t.lcuuid
}

func (t *PodNode) ID() int {
	return t.id
}

func (t *PodNode) DomainLcuuid() string {
	return t.domainLcuuid
}

func (t *PodNode) Name() string {
	return t.name
}

func (t *PodNode) RegionID() int {
	return t.regionID
}

func (t *PodNode) AZID() int {
	return t.azID
}

func (t *PodNode) VPCID() int {
	return t.vpcID
}

func (t *PodNode) PodClusterID() int {
	return t.podClusterID
}

func (t *PodNode) VMID() int {
	return t.vmID
}

func (t *PodNode) SetVMID(vmID int) {
	t.vmID = vmID
}

func (t *PodNode) reset(dbItem *metadbmodel.PodNode, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.domainLcuuid = dbItem.Domain
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.vpcID = dbItem.VPCID
	t.podClusterID = dbItem.PodClusterID
}

func NewPodNodeCollection(t *Tool) *PodNodeCollection {
	c := new(PodNodeCollection)
	c.collection = newCollectionBuilder[*PodNode]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_NODE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodNode { return new(metadbmodel.PodNode) }).
		withCacheItemFactory(func() *PodNode { return new(PodNode) }).
		build()
	return c
}

// PodNodeCollection defines a collection that maps individual fields to the PodNode cache data structure.
type PodNodeCollection struct {
	collection[*PodNode, *metadbmodel.PodNode]
}
