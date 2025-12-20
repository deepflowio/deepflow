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

// PodIngress defines cache data structure.
type PodIngress struct {
	lcuuid         string
	id             int
	name           string
	regionID       int
	azID           int
	podNamespaceID int
	podClusterID   int
}

func (t *PodIngress) IsValid() bool {
	return t.lcuuid != ""
}

func (t *PodIngress) Lcuuid() string {
	return t.lcuuid
}

func (t *PodIngress) ID() int {
	return t.id
}

func (t *PodIngress) Name() string {
	return t.name
}

func (t *PodIngress) RegionID() int {
	return t.regionID
}

func (t *PodIngress) AZID() int {
	return t.azID
}

func (t *PodIngress) PodNamespaceID() int {
	return t.podNamespaceID
}

func (t *PodIngress) PodClusterID() int {
	return t.podClusterID
}

func (t *PodIngress) reset(dbItem *metadbmodel.PodIngress, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.podNamespaceID = dbItem.PodNamespaceID
	t.podClusterID = dbItem.PodClusterID
}

func NewPodIngressCollection(t *Tool) *PodIngressCollection {
	c := new(PodIngressCollection)
	c.collection = newCollectionBuilder[*PodIngress]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_INGRESS_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodIngress { return new(metadbmodel.PodIngress) }).
		withCacheItemFactory(func() *PodIngress { return new(PodIngress) }).
		build()
	return c
}

// PodIngressCollection defines a collection that maps individual fields to the PodIngress cache data structure.
type PodIngressCollection struct {
	collection[*PodIngress, *metadbmodel.PodIngress]
}
