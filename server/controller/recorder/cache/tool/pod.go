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

// Pod defines cache data structure.
type Pod struct {
	lcuuid         string
	id             int
	domainLcuuid   string
	name           string
	regionID       int
	azID           int
	vpcID          int
	podClusterID   int
	podNamespaceID int
	podGroupID     int
	podNodeID      int
}

func (t *Pod) IsValid() bool {
	return t.lcuuid != ""
}

func (t *Pod) Lcuuid() string {
	return t.lcuuid
}

func (t *Pod) ID() int {
	return t.id
}

func (t *Pod) DomainLcuuid() string {
	return t.domainLcuuid
}

func (t *Pod) Name() string {
	return t.name
}

func (t *Pod) RegionID() int {
	return t.regionID
}

func (t *Pod) AZID() int {
	return t.azID
}

func (t *Pod) VPCID() int {
	return t.vpcID
}

func (t *Pod) PodClusterID() int {
	return t.podClusterID
}

func (t *Pod) PodNamespaceID() int {
	return t.podNamespaceID
}

func (t *Pod) PodGroupID() int {
	return t.podGroupID
}

func (t *Pod) PodNodeID() int {
	return t.podNodeID
}

func (t *Pod) reset(dbItem *metadbmodel.Pod, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.domainLcuuid = dbItem.Domain
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.vpcID = dbItem.VPCID
	t.podClusterID = dbItem.PodClusterID
	t.podNamespaceID = dbItem.PodNamespaceID
	t.podGroupID = dbItem.PodGroupID
	t.podNodeID = dbItem.PodNodeID
}

func NewPodCollection(t *Tool) *PodCollection {
	c := new(PodCollection)
	c.resetExt()
	c.collection = newCollectionBuilder[*Pod]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.Pod { return new(metadbmodel.Pod) }).
		withCacheItemFactory(func() *Pod { return new(Pod) }).
		withExtender(c).
		build()
	return c
}

// PodCollection defines a collection that maps individual fields to the Pod cache data structure.
type PodCollection struct {
	collection[*Pod, *metadbmodel.Pod]
	PodCollectionExt
}
