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

// PodGroupConfigMapConnection defines cache data structure.
type PodGroupConfigMapConnection struct {
	lcuuid      string
	id          int
	configMapID int
	podGroupID  int
}

func (t *PodGroupConfigMapConnection) IsValid() bool {
	return t.lcuuid != ""
}

func (t *PodGroupConfigMapConnection) Lcuuid() string {
	return t.lcuuid
}

func (t *PodGroupConfigMapConnection) ID() int {
	return t.id
}

func (t *PodGroupConfigMapConnection) ConfigMapID() int {
	return t.configMapID
}

func (t *PodGroupConfigMapConnection) PodGroupID() int {
	return t.podGroupID
}

func (t *PodGroupConfigMapConnection) reset(dbItem *metadbmodel.PodGroupConfigMapConnection, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.configMapID = dbItem.ConfigMapID
	t.podGroupID = dbItem.PodGroupID
}

func NewPodGroupConfigMapConnectionCollection(t *Tool) *PodGroupConfigMapConnectionCollection {
	c := new(PodGroupConfigMapConnectionCollection)
	c.collection = newCollectionBuilder[*PodGroupConfigMapConnection]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_POD_GROUP_CONFIG_MAP_CONNECTION_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.PodGroupConfigMapConnection { return new(metadbmodel.PodGroupConfigMapConnection) }).
		withCacheItemFactory(func() *PodGroupConfigMapConnection { return new(PodGroupConfigMapConnection) }).
		build()
	return c
}

// PodGroupConfigMapConnectionCollection defines a collection that maps individual fields to the PodGroupConfigMapConnection cache data structure.
type PodGroupConfigMapConnectionCollection struct {
	collection[*PodGroupConfigMapConnection, *metadbmodel.PodGroupConfigMapConnection]
}
