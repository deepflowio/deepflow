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

// PodReplicaSet defines cache data structure.
type PodReplicaSet struct {
	lcuuid         string
	id             int
	name           string
	regionID       int
	azID           int
	podGroupID     int
	podNamespaceID int
	podClusterID   int
}

func (t *PodReplicaSet) IsValid() bool {
	return t.lcuuid != ""
}

func (t *PodReplicaSet) Lcuuid() string {
	return t.lcuuid
}

func (t *PodReplicaSet) ID() int {
	return t.id
}

func (t *PodReplicaSet) Name() string {
	return t.name
}

func (t *PodReplicaSet) RegionID() int {
	return t.regionID
}

func (t *PodReplicaSet) AZID() int {
	return t.azID
}

func (t *PodReplicaSet) PodGroupID() int {
	return t.podGroupID
}

func (t *PodReplicaSet) PodNamespaceID() int {
	return t.podNamespaceID
}

func (t *PodReplicaSet) PodClusterID() int {
	return t.podClusterID
}

func (t *PodReplicaSet) reset(dbItem *metadbmodel.PodReplicaSet, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.podGroupID = dbItem.PodGroupID
	t.podNamespaceID = dbItem.PodNamespaceID
	t.podClusterID = dbItem.PodClusterID
}

func NewPodReplicaSetCollection(t *Tool) *PodReplicaSetCollection {
	c := new(PodReplicaSetCollection)
	c.collection = newCollectionBuilder[*PodReplicaSet]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_REPLICA_SET_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodReplicaSet { return new(metadbmodel.PodReplicaSet) }).
		withCacheItemFactory(func() *PodReplicaSet { return new(PodReplicaSet) }).
		build()
	return c
}

// PodReplicaSetCollection defines a collection that maps individual fields to the PodReplicaSet cache data structure.
type PodReplicaSetCollection struct {
	collection[*PodReplicaSet, *metadbmodel.PodReplicaSet]
}
