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

type LANIPCollectionExt struct {
	vInterfaceIDToItems map[int][]*LANIP // 一对多映射
}

func (c *LANIPCollection) resetExt() {
	c.vInterfaceIDToItems = make(map[int][]*LANIP)
}

// GetByVInterfaceID returns all LANIP items with the specified vInterfaceID
func (c *LANIPCollection) GetByVInterfaceID(vInterfaceID int) []*LANIP {
	return c.vInterfaceIDToItems[vInterfaceID]
}

// OnAfterAdd implements CollectionExtender interface for one-to-many mapping
func (c *LANIPCollection) OnAfterAdd(item *LANIP, dbItem *metadbmodel.LANIP) {
	c.vInterfaceIDToItems[item.VInterfaceID()] = append(c.vInterfaceIDToItems[item.VInterfaceID()], item)
}

// OnAfterUpdate implements CollectionExtender interface
func (c *LANIPCollection) OnAfterUpdate(item *LANIP, dbItem *metadbmodel.LANIP) {
	// Remove from old mapping if vInterfaceID changed
	for vInterfaceID, items := range c.vInterfaceIDToItems {
		for i, lanipItem := range items {
			if lanipItem == item && vInterfaceID != item.VInterfaceID() {
				// Remove from old vInterfaceID group
				c.vInterfaceIDToItems[vInterfaceID] = append(items[:i], items[i+1:]...)
				break
			}
		}
	}

	// Add to new mapping
	newVInterfaceID := item.VInterfaceID()
	found := false
	for _, existingItem := range c.vInterfaceIDToItems[newVInterfaceID] {
		if existingItem == item {
			found = true
			break
		}
	}
	if !found {
		c.vInterfaceIDToItems[newVInterfaceID] = append(c.vInterfaceIDToItems[newVInterfaceID], item)
	}
}

// OnAfterDelete implements CollectionExtender interface
func (c *LANIPCollection) OnAfterDelete(item *LANIP, dbItem *metadbmodel.LANIP) {
	vInterfaceID := item.VInterfaceID()
	items := c.vInterfaceIDToItems[vInterfaceID]

	for i, lanipItem := range items {
		if lanipItem.ID() == item.ID() {
			c.vInterfaceIDToItems[vInterfaceID] = append(items[:i], items[i+1:]...)
			break
		}
	}
}
