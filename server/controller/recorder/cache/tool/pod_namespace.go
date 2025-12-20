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

// PodNamespace defines cache data structure.
type PodNamespace struct {
	lcuuid       string
	id           int
	name         string
	regionID     int
	azID         int
	podClusterID int
}

func (t *PodNamespace) IsValid() bool {
	return t.lcuuid != ""
}

func (t *PodNamespace) Lcuuid() string {
	return t.lcuuid
}

func (t *PodNamespace) ID() int {
	return t.id
}

func (t *PodNamespace) Name() string {
	return t.name
}

func (t *PodNamespace) RegionID() int {
	return t.regionID
}

func (t *PodNamespace) AZID() int {
	return t.azID
}

func (t *PodNamespace) PodClusterID() int {
	return t.podClusterID
}

func (t *PodNamespace) reset(dbItem *metadbmodel.PodNamespace, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.podClusterID = dbItem.PodClusterID
}

func NewPodNamespaceCollection(t *Tool) *PodNamespaceCollection {
	c := new(PodNamespaceCollection)
	c.collection = newCollectionBuilder[*PodNamespace]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_NAMESPACE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodNamespace { return new(metadbmodel.PodNamespace) }).
		withCacheItemFactory(func() *PodNamespace { return new(PodNamespace) }).
		build()
	return c
}

// PodNamespaceCollection defines a collection that maps individual fields to the PodNamespace cache data structure.
type PodNamespaceCollection struct {
	collection[*PodNamespace, *metadbmodel.PodNamespace]
}
