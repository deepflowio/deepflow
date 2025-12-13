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

const (
	logActionAdd = iota
	logActionUpdate
	logActionDelete

	hookerAfterAdd = iota
	hookerAfterUpdate
	hookerAfterDelete
)

// CacheItem defines cache object must implement the interface
type CacheItem[D DBItem] interface {
	ID() int
	Lcuuid() string
	IsValid() bool // check whether the item is valid

	reset(dbItem D, tool *Tool) // reset the item with dbItem
}

// DBItem defines database object must implement the interface
type DBItem interface {
	GetID() int
	GetLcuuid() string
}

// CollectionExtender allows specific collections to extend basic operations
type CollectionExtender[T CacheItem[D], D DBItem] interface {
	OnAfterAdd(item T, dbItem D)
	OnAfterUpdate(item T, dbItem D)
	OnAfterDelete(item T, dbItem D)
}

// collectionBuilder use builder pattern to build collection
type collectionBuilder[T CacheItem[D], D DBItem] struct {
	collection[T, D]
}

// newCollectionBuilder
func newCollectionBuilder[T CacheItem[D], D DBItem]() *collectionBuilder[T, D] {
	return &collectionBuilder[T, D]{}
}

// withResourceType 设置资源类型
func (b *collectionBuilder[T, D]) withResourceType(resourceType string) *collectionBuilder[T, D] {
	b.resourceType = resourceType
	return b
}

func (b *collectionBuilder[T, D]) withTool(tool *Tool) *collectionBuilder[T, D] {
	b.tool = tool
	return b
}

// withExtender 设置扩展器
func (b *collectionBuilder[T, D]) withExtender(extender CollectionExtender[T, D]) *collectionBuilder[T, D] {
	b.extender = extender
	return b
}

// withDBItemFactory 设置数据库对象工厂函数
func (b *collectionBuilder[T, D]) withDBItemFactory(factory func() D) *collectionBuilder[T, D] {
	b.dbItemFactory = factory
	return b
}

// withCacheItemFactory 设置缓存对象工厂函数
func (b *collectionBuilder[T, D]) withCacheItemFactory(factory func() T) *collectionBuilder[T, D] {
	b.cacheItemFactory = factory
	return b
}

// build 构建集合
func (b *collectionBuilder[T, D]) build() collection[T, D] {
	return collection[T, D]{
		resourceType:     b.resourceType,
		tool:             b.tool,
		extender:         b.extender,
		dbItemFactory:    b.dbItemFactory,
		cacheItemFactory: b.cacheItemFactory,

		lcuuidToItem: make(map[string]T),
		idToItem:     make(map[int]T),
	}
}

// 优化后的 Collection
type collection[T CacheItem[D], D DBItem] struct {
	resourceType string
	tool         *Tool

	extender         CollectionExtender[T, D]
	dbItemFactory    func() D
	cacheItemFactory func() T

	lcuuidToItem map[string]T
	idToItem     map[int]T
}

func (oc *collection[T, D]) Add(dbItem D) {
	item := oc.cacheItemFactory()
	item.reset(dbItem, oc.tool)
	oc.lcuuidToItem[dbItem.GetLcuuid()] = item
	oc.idToItem[dbItem.GetID()] = item
	if oc.extender != nil {
		oc.extender.OnAfterAdd(item, dbItem)
	}
	oc.tool.GetLogFunc()(addToToolMap(oc.resourceType, dbItem.GetLcuuid()), oc.tool.metadata.LogPrefixes)
}

func (oc *collection[T, D]) Update(dbItem D) {
	if existingItem, ok := oc.idToItem[dbItem.GetID()]; ok {
		existingItem.reset(dbItem, oc.tool)
		if oc.extender != nil {
			oc.extender.OnAfterUpdate(existingItem, dbItem)
		}
		oc.tool.GetLogFunc()(updateToolMap(oc.resourceType, dbItem.GetLcuuid()), oc.tool.metadata.LogPrefixes)
		return
	}
	// 如果缓存中不存在，则添加
	oc.Add(dbItem)
}

func (oc *collection[T, D]) Delete(dbItem D) {
	item, exists := oc.idToItem[dbItem.GetID()]
	delete(oc.lcuuidToItem, dbItem.GetLcuuid())
	delete(oc.idToItem, dbItem.GetID())
	if exists && oc.extender != nil {
		oc.extender.OnAfterDelete(item, dbItem)
	}
	oc.tool.GetLogFunc()(deleteFromToolMap(oc.resourceType, dbItem.GetLcuuid()), oc.tool.metadata.LogPrefixes)
}

// GetByLcuuid returns the item by lcuuid.
// If not found, returns the zero value of T.T can be checked whether it is valid by IsValid() method.
func (oc *collection[T, D]) GetByLcuuid(lcuuid string) T {
	empty := oc.cacheItemFactory()
	if lcuuid == "" {
		return empty
	}
	if item, ok := oc.lcuuidToItem[lcuuid]; ok {
		return item
	}
	return empty
}

// GetOrLoadByLcuuid first tries to get the item from the cache, if it is not in the cache,
// it queries from the database, adds it to the cache and returns it.
func (oc *collection[T, D]) GetOrLoadByLcuuid(lcuuid string) T {
	empty := oc.cacheItemFactory()
	if lcuuid == "" {
		return empty
	}

	if item, ok := oc.lcuuidToItem[lcuuid]; ok {
		return item
	}

	if oc.dbItemFactory == nil {
		log.Warningf("dbItemFactory is nil, cannot load %s (lcuuid: %s) from db", oc.resourceType, lcuuid)
		return empty
	}
	log.Warning(collectionNotFoundByLcuuid(oc.resourceType, lcuuid), oc.tool.metadata.LogPrefixes)

	dbItem := oc.dbItemFactory()
	result := oc.tool.metadata.GetDB().Where("lcuuid = ?", lcuuid).First(dbItem)
	if result.Error != nil {
		log.Error(dbResourceByLcuuidNotFound(oc.resourceType, lcuuid), oc.tool.metadata.LogPrefixes)
		return empty
	}

	oc.Add(dbItem)
	return oc.lcuuidToItem[lcuuid]
}

// GetByID returns the item by ID.
// If not found, returns the zero value of T.T can be checked whether it is valid by IsValid() method.
func (oc *collection[T, D]) GetByID(id int) T {
	empty := oc.cacheItemFactory()
	if id == 0 {
		return empty
	}
	if item, ok := oc.idToItem[id]; ok {
		return item
	}
	return empty
}

// GetOrLoadByID first tries to get the item from the cache, if it is not in the cache,
// it queries from the database, adds it to the cache and returns it.
func (oc *collection[T, D]) GetOrLoadByID(id int) T {
	empty := oc.cacheItemFactory()
	if id == 0 {
		return empty
	}
	if item, ok := oc.idToItem[id]; ok {
		return item
	}

	if oc.dbItemFactory == nil {
		log.Warningf("dbItemFactory is nil, cannot load %s (id: %d) from db", oc.resourceType, id)
		return empty
	}
	log.Warning(collectionNotFoundByID(oc.resourceType, id), oc.tool.metadata.LogPrefixes)

	dbItem := oc.dbItemFactory()
	result := oc.tool.metadata.GetDB().Where("id = ?", id).First(dbItem)
	if result.Error != nil {
		log.Error(dbResourceByIDNotFound(oc.resourceType, id), oc.tool.metadata.LogPrefixes)
		return empty
	}

	oc.Add(dbItem)
	return oc.idToItem[id]
}
