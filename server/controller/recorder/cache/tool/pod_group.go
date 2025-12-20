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

// PodGroup defines cache data structure.
type PodGroup struct {
	lcuuid         string
	id             int
	name           string
	gType          int
	regionID       int
	azID           int
	podNamespaceID int
	podClusterID   int
}

func (t *PodGroup) IsValid() bool {
	return t.lcuuid != ""
}

func (t *PodGroup) Lcuuid() string {
	return t.lcuuid
}

func (t *PodGroup) ID() int {
	return t.id
}

func (t *PodGroup) Name() string {
	return t.name
}

func (t *PodGroup) Type() int {
	return t.gType
}

func (t *PodGroup) RegionID() int {
	return t.regionID
}

func (t *PodGroup) AZID() int {
	return t.azID
}

func (t *PodGroup) PodNamespaceID() int {
	return t.podNamespaceID
}

func (t *PodGroup) PodClusterID() int {
	return t.podClusterID
}

func (t *PodGroup) reset(dbItem *metadbmodel.PodGroup, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.gType = dbItem.Type
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.podNamespaceID = dbItem.PodNamespaceID
	t.podClusterID = dbItem.PodClusterID
}

func NewPodGroupCollection(t *Tool) *PodGroupCollection {
	c := new(PodGroupCollection)
	c.collection = newCollectionBuilder[*PodGroup]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodGroup { return new(metadbmodel.PodGroup) }).
		withCacheItemFactory(func() *PodGroup { return new(PodGroup) }).
		build()
	return c
}

// PodGroupCollection defines a collection that maps individual fields to the PodGroup cache data structure.
type PodGroupCollection struct {
	collection[*PodGroup, *metadbmodel.PodGroup]
}
