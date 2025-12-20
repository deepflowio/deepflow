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
	"strings"

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type PodCollectionExt struct {
	containerIDToPodID map[string]int
}

func (c *PodCollection) resetExt() {
	c.containerIDToPodID = make(map[string]int)
}

// GetByContainerID returns the Pod by its containerID
func (c *PodCollection) GetByContainerID(containerID string) *Pod {
	return c.GetByID(c.containerIDToPodID[containerID])
}

// OnAfterAdd implements CollectionExtender interface
// Maintains containerID to podID mapping when pod is added
func (c *PodCollection) OnAfterAdd(item *Pod, dbItem *metadbmodel.Pod) {
	for _, containerID := range strings.Split(dbItem.ContainerIDs, ", ") {
		if containerID != "" {
			c.containerIDToPodID[containerID] = item.ID()
		}
	}
}

// OnAfterUpdate implements CollectionExtender interface
func (c *PodCollection) OnAfterUpdate(item *Pod, dbItem *metadbmodel.Pod) {
	// Remove old containerID mappings for this pod
	for containerID, podID := range c.containerIDToPodID {
		if podID == item.ID() {
			delete(c.containerIDToPodID, containerID)
		}
	}

	// Add new containerID mappings
	for _, containerID := range strings.Split(dbItem.ContainerIDs, ", ") {
		if containerID != "" {
			c.containerIDToPodID[containerID] = item.ID()
		}
	}
}

// OnAfterDelete implements CollectionExtender interface
// Removes containerID mappings when pod is deleted
func (c *PodCollection) OnAfterDelete(item *Pod, dbItem *metadbmodel.Pod) {
	for _, containerID := range strings.Split(dbItem.ContainerIDs, ", ") {
		if containerID != "" {
			delete(c.containerIDToPodID, containerID)
		}
	}
}
