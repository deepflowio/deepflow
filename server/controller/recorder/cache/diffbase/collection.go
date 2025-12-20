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

package diffbase

import (
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

type ResourceBase struct {
	Sequence int    `json:"sequence"`
	Lcuuid   string `json:"lcuuid"`
}

func (d ResourceBase) GetSequence() int {
	return d.Sequence
}

func (d ResourceBase) GetLcuuid() string {
	return d.Lcuuid
}

func (d *ResourceBase) SetSequence(sequence int) {
	d.Sequence = sequence
}

func (d *ResourceBase) init(sequence int, lcuuid string) {
	d.Sequence = sequence
	d.Lcuuid = lcuuid
}

// CacheItem defines cache object must implement the interface
type CacheItem[D DBItem] interface {
	GetLcuuid() string
	GetSequence() int
	init(sequence int, lcuuid string)
	reset(dbItem D, tool *tool.Tool) // reset the item with dbItem
}

// DBItem defines database object must implement the interface
type DBItem interface {
	GetID() int
	GetLcuuid() string
}

// collectionBuilder use builder pattern to build collection
type collectionBuilder[T CacheItem[D], D DBItem] struct {
	collection[T, D]
}

func newCollectionBuilder[T CacheItem[D], D DBItem]() *collectionBuilder[T, D] {
	return &collectionBuilder[T, D]{}
}

func (b *collectionBuilder[T, D]) withResourceType(resourceType string) *collectionBuilder[T, D] {
	b.resourceType = resourceType
	return b
}

func (b *collectionBuilder[T, D]) withTool(tool *tool.Tool) *collectionBuilder[T, D] {
	b.tool = tool
	return b
}

func (b *collectionBuilder[T, D]) withDBItemFactory(factory func() D) *collectionBuilder[T, D] {
	b.dbItemFactory = factory
	return b
}

func (b *collectionBuilder[T, D]) withCacheItemFactory(factory func() T) *collectionBuilder[T, D] {
	b.cacheItemFactory = factory
	return b
}

func (b *collectionBuilder[T, D]) build() collection[T, D] {
	return collection[T, D]{
		resourceType:     b.resourceType,
		tool:             b.tool,
		dbItemFactory:    b.dbItemFactory,
		cacheItemFactory: b.cacheItemFactory,

		lcuuidToItem: make(map[string]T),
	}
}

type collection[T CacheItem[D], D DBItem] struct {
	resourceType string
	tool         *tool.Tool

	dbItemFactory    func() D
	cacheItemFactory func() T

	lcuuidToItem map[string]T
}

func (c *collection[T, D]) GetByLcuuid(lcuuid string) T {
	empty := c.cacheItemFactory()
	if lcuuid == "" {
		return empty
	}
	if item, ok := c.lcuuidToItem[lcuuid]; ok {
		return item
	}
	return empty
}

func (c *collection[T, D]) GetAll() map[string]T {
	return c.lcuuidToItem
}

func (c *collection[T, D]) Add(dbItem D, seq int) {
	item := c.cacheItemFactory()
	item.init(seq, dbItem.GetLcuuid())
	item.reset(dbItem, c.tool)
	c.lcuuidToItem[dbItem.GetLcuuid()] = item
	c.tool.GetLogFunc()(addDiffBase(c.resourceType, dbItem.GetLcuuid()), c.tool.Metadata().LogPrefixes)
}

func (c *collection[T, D]) Update(dbItem D, seq int) {
	if existingItem, ok := c.lcuuidToItem[dbItem.GetLcuuid()]; ok {
		existingItem.reset(dbItem, c.tool)
		c.tool.GetLogFunc()(updateDiffBase(c.resourceType, dbItem.GetLcuuid()), c.tool.Metadata().LogPrefixes)
		return
	}
	// if cache item not exists, add it
	log.Errorf("%s cache item not found (lcuuid: %s), add it", c.resourceType, dbItem.GetLcuuid(), c.tool.Metadata().LogPrefixes)
	c.Add(dbItem, seq)
}

func (c *collection[T, D]) Delete(dbItem D) {
	delete(c.lcuuidToItem, dbItem.GetLcuuid())
	c.tool.GetLogFunc()(deleteDiffBase(c.resourceType, dbItem.GetLcuuid()), c.tool.Metadata().LogPrefixes)
}
