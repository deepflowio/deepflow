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

type WanIpCollectionExt struct {
	vInterfaceIDToItems map[int][]*WanIp // 一对多映射
}

func (c *WanIpCollection) resetExt() {
	c.vInterfaceIDToItems = make(map[int][]*WanIp)
}

// GetByVInterfaceID returns all WANIP items with the specified vInterfaceID
func (c *WanIpCollection) GetByVInterfaceID(vInterfaceID int) []*WanIp {
	return c.vInterfaceIDToItems[vInterfaceID]
}

// OnAfterAdd implements CollectionExtender interface for one-to-many mapping
func (c *WanIpCollection) OnAfterAdd(item *WanIp, dbItem *metadbmodel.WANIP) {
	c.vInterfaceIDToItems[item.VinterfaceId()] = append(c.vInterfaceIDToItems[item.VinterfaceId()], item)
}

// OnAfterUpdate implements CollectionExtender interface
func (c *WanIpCollection) OnAfterUpdate(item *WanIp, dbItem *metadbmodel.WANIP) {
	// Remove from old mapping if vInterfaceID changed
	for vInterfaceID, items := range c.vInterfaceIDToItems {
		for i, wanipItem := range items {
			if wanipItem == item && vInterfaceID != item.VinterfaceId() {
				// Remove from old vInterfaceID group
				c.vInterfaceIDToItems[vInterfaceID] = append(items[:i], items[i+1:]...)
				break
			}
		}
	}

	// Add to new mapping
	newVInterfaceID := item.VinterfaceId()
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
func (c *WanIpCollection) OnAfterDelete(item *WanIp, dbItem *metadbmodel.WANIP) {
	vInterfaceID := item.VinterfaceId()
	items := c.vInterfaceIDToItems[vInterfaceID]

	for i, wanipItem := range items {
		if wanipItem.Id() == item.Id() {
			c.vInterfaceIDToItems[vInterfaceID] = append(items[:i], items[i+1:]...)
			break
		}
	}
}
