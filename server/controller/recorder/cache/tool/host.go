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

// Host defines cache data structure.
type Host struct {
	lcuuid   string
	id       int
	name     string
	regionID int
	azID     int
	ip       string
}

func (t *Host) IsValid() bool {
	return t.lcuuid != ""
}

func (t *Host) Lcuuid() string {
	return t.lcuuid
}

func (t *Host) ID() int {
	return t.id
}

func (t *Host) Name() string {
	return t.name
}

func (t *Host) Region() int {
	return t.regionID
}

func (t *Host) AZ() int {
	return t.azID
}

func (t *Host) IP() string {
	return t.ip
}

func (t *Host) reset(dbItem *metadbmodel.Host, tool *Tool) {
	t.lcuuid = dbItem.Lcuuid
	t.id = dbItem.ID
	t.name = dbItem.Name
	t.regionID = tool.Region().GetByLcuuid(dbItem.Region).ID()
	t.azID = tool.AZ().GetByLcuuid(dbItem.AZ).ID()
	t.ip = dbItem.IP
}

func NewHostCollection(t *Tool) *HostCollection {
	c := new(HostCollection)
	c.ipToItem = make(map[string]*Host)
	c.collection = newCollectionBuilder[*Host]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_HOST_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.Host { return new(metadbmodel.Host) }).
		withCacheItemFactory(func() *Host { return new(Host) }).
		withExtender(c).
		build()
	return c
}

// HostCollection defines a collection that maps individual fields to the Host cache data structure.
type HostCollection struct {
	collection[*Host, *metadbmodel.Host]
	ipToItem map[string]*Host
}

// OnAfterAdd implements CollectionExtender interface
func (c *HostCollection) OnAfterAdd(item *Host, dbItem *metadbmodel.Host) {
	if item.IP() != "" {
		c.ipToItem[item.IP()] = item
	}
}

// OnAfterUpdate implements CollectionExtender interface
func (c *HostCollection) OnAfterUpdate(item *Host, dbItem *metadbmodel.Host) {
	// Remove old ip mapping if exists
	for ip, hostItem := range c.ipToItem {
		if hostItem == item && ip != item.IP() {
			delete(c.ipToItem, ip)
			break
		}
	}
	// Add new ip mapping
	if item.IP() != "" {
		c.ipToItem[item.IP()] = item
	}
}

// OnAfterDelete implements CollectionExtender interface
func (c *HostCollection) OnAfterDelete(item *Host, dbItem *metadbmodel.Host) {
	if item.IP() != "" {
		delete(c.ipToItem, item.IP())
	}
}

// GetOrLoadByIP returns the Host by its ip, loading from DB if not found in cache.
func (c *HostCollection) GetOrLoadByIP(ip string) *Host {
	if ip == "" {
		return new(Host)
	}

	item, ok := c.ipToItem[ip]
	if ok {
		return item
	}
	log.Warning("cache %s (ip: %s) not found", c.resourceType, ip)

	var dbItem *metadbmodel.Host
	if result := c.tool.metadata.GetDB().Where("ip = ?", ip).First(&dbItem); result.RowsAffected == 1 {
		c.Add(dbItem)
		return c.ipToItem[ip]
	} else {
		log.Error("db %s (ip: %s) not found", c.resourceType, ip)
		return new(Host)
	}
}
