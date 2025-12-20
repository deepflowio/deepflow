/**
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

package diffbase

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

type ConfigMap struct {
	ResourceBase
	Name     string
	Data     string
	DataHash string
}

func (a *ConfigMap) reset(dbItem *metadbmodel.ConfigMap, tool *tool.Tool) {
	a.Name = dbItem.Name
	a.Data = string(dbItem.Data)
	a.DataHash = dbItem.DataHash
}

// ToLoggable converts ConfigMap to a loggable format, excluding sensitive fields
func (a ConfigMap) ToLoggable() interface{} {
	copied := a
	copied.Data = "**HIDDEN**"
	return copied
}

func NewConfigMapCollection(t *tool.Tool) *ConfigMapCollection {
	c := new(ConfigMapCollection)
	c.collection = newCollectionBuilder[*ConfigMap]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_CONFIG_MAP_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.ConfigMap { return new(metadbmodel.ConfigMap) }).
		withCacheItemFactory(func() *ConfigMap { return new(ConfigMap) }).
		build()
	return c
}

type ConfigMapCollection struct {
	collection[*ConfigMap, *metadbmodel.ConfigMap]
}
