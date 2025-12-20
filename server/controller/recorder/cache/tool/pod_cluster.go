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

// PodCluster defines cache data structure.
type PodCluster struct {
	lcuuid   string
	id       int
	name     string
	regionID int
	azID     int
	vpcID    int
}

func (t *PodCluster) IsValid() bool {
	return t.lcuuid != ""
}

func (t *PodCluster) Lcuuid() string {
	return t.lcuuid
}

func (t *PodCluster) ID() int {
	return t.id
}

func (t *PodCluster) Name() string {
	return t.name
}

func (t *PodCluster) RegionID() int {
	return t.regionID
}

func (t *PodCluster) AZID() int {
	return t.azID
}

func (t *PodCluster) VPCID() int {
	return t.vpcID
}

func (t *PodCluster) reset(dbItem *metadbmodel.PodCluster, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.vpcID = dbItem.VPCID
}

func NewPodClusterCollection(t *Tool) *PodClusterCollection {
	c := new(PodClusterCollection)
	c.collection = newCollectionBuilder[*PodCluster]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_CLUSTER_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodCluster { return new(metadbmodel.PodCluster) }).
		withCacheItemFactory(func() *PodCluster { return new(PodCluster) }).
		build()
	return c
}

// PodClusterCollection defines a collection that maps individual fields to the PodCluster cache data structure.
type PodClusterCollection struct {
	collection[*PodCluster, *metadbmodel.PodCluster]
}
