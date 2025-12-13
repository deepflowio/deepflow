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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

// OnAfterAdd implements CollectionExtender interface
// Maintains ConfigMap's podGroupIDs when connection is added
func (c *PodGroupConfigMapConnectionCollection) OnAfterAdd(item *PodGroupConfigMapConnection, dbItem *metadbmodel.PodGroupConfigMapConnection) {
	c.tool.ConfigMap().GetByID(item.ConfigMapID()).AddPodGroupID(item.PodGroupID())
}

// OnAfterUpdate implements CollectionExtender interface
func (c *PodGroupConfigMapConnectionCollection) OnAfterUpdate(item *PodGroupConfigMapConnection, dbItem *metadbmodel.PodGroupConfigMapConnection) {
	// For connection tables, update is usually just add/delete operations
	// No special logic needed for update
}

// OnAfterDelete implements CollectionExtender interface
// Maintains ConfigMap's podGroupIDs when connection is deleted
func (c *PodGroupConfigMapConnectionCollection) OnAfterDelete(item *PodGroupConfigMapConnection, dbItem *metadbmodel.PodGroupConfigMapConnection) {
	c.tool.ConfigMap().GetByID(item.ConfigMapID()).RemovePodGroupID(item.PodGroupID())
}
