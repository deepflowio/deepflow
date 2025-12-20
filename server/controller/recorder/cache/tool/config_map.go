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
	mapset "github.com/deckarep/golang-set/v2"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

// ConfigMap defines cache data structure.
type ConfigMap struct {
	lcuuid      string
	id          int
	name        string
	podGroupIDs mapset.Set[int] // data source: pod_group_config_map_connection
}

func (t *ConfigMap) IsValid() bool {
	return t.lcuuid != ""
}

func (t *ConfigMap) Lcuuid() string {
	return t.lcuuid
}

func (t *ConfigMap) ID() int {
	return t.id
}

func (t *ConfigMap) Name() string {
	return t.name
}

func (t *ConfigMap) PodGroupIDs() mapset.Set[int] {
	return t.podGroupIDs
}

func (t *ConfigMap) PodGroupIDsToSlice() []int {
	return t.podGroupIDs.ToSlice()
}

func (t *ConfigMap) AddPodGroupID(id int) {
	t.podGroupIDs.Add(id)
}

func (t *ConfigMap) RemovePodGroupID(id int) {
	t.podGroupIDs.Remove(id)
}

func (t *ConfigMap) reset(dbItem *metadbmodel.ConfigMap, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.podGroupIDs = mapset.NewSet[int]()
}

func NewConfigMapCollection(t *Tool) *ConfigMapCollection {
	c := new(ConfigMapCollection)
	c.collection = newCollectionBuilder[*ConfigMap]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_CONFIG_MAP_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.ConfigMap { return new(metadbmodel.ConfigMap) }).
		withCacheItemFactory(func() *ConfigMap { return new(ConfigMap) }).
		build()
	return c
}

// ConfigMapCollection defines a collection that maps individual fields to the ConfigMap cache data structure.
type ConfigMapCollection struct {
	collection[*ConfigMap, *metadbmodel.ConfigMap]
}
