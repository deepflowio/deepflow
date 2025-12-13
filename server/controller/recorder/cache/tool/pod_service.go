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

// PodService defines cache data structure.
type PodService struct {
	lcuuid         string
	id             int
	name           string
	regionID       int
	azID           int
	vpcID          int
	podClusterID   int
	podNamespaceID int
}

func (t *PodService) IsValid() bool {
	return t.lcuuid != ""
}

func (t *PodService) Lcuuid() string {
	return t.lcuuid
}

func (t *PodService) ID() int {
	return t.id
}

func (t *PodService) Name() string {
	return t.name
}

func (t *PodService) RegionID() int {
	return t.regionID
}

func (t *PodService) AZID() int {
	return t.azID
}

func (t *PodService) VPCID() int {
	return t.vpcID
}

func (t *PodService) PodClusterID() int {
	return t.podClusterID
}

func (t *PodService) PodNamespaceID() int {
	return t.podNamespaceID
}

func (t *PodService) reset(dbItem *metadbmodel.PodService, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.vpcID = dbItem.VPCID
	t.podClusterID = dbItem.PodClusterID
	t.podNamespaceID = dbItem.PodNamespaceID
}

func NewPodServiceCollection(t *Tool) *PodServiceCollection {
	c := new(PodServiceCollection)
	c.collection = newCollectionBuilder[*PodService]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_SERVICE_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodService { return new(metadbmodel.PodService) }).
		withCacheItemFactory(func() *PodService { return new(PodService) }).
		build()
	return c
}

// PodServiceCollection defines a collection that maps individual fields to the PodService cache data structure.
type PodServiceCollection struct {
	collection[*PodService, *metadbmodel.PodService]
}
