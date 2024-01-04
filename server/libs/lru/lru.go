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

package lru

import (
	"container/list"
)

type Cache[Key comparable, Value any] struct {
	capacity int
	lruList  *list.List
	cache    map[Key]*list.Element
}

type entry[Key comparable, Value any] struct {
	key   Key
	value Value
}

func NewCache[Key comparable, Value any](maxEntries int) *Cache[Key, Value] {
	return &Cache[Key, Value]{
		capacity: maxEntries,
		lruList:  list.New(),
		cache:    make(map[Key]*list.Element),
	}
}

// When the key already exists, return its current value in lru and true
// otherwise insert the new key-value and return nil and false
func (c *Cache[Key, Value]) AddOrGet(key Key, value Value) (Value, bool) {
	if c.cache == nil {
		c.cache = make(map[Key]*list.Element)
		c.lruList = list.New()
	}
	if ee, ok := c.cache[key]; ok {
		c.lruList.MoveToFront(ee)
		return ee.Value.(*entry[Key, Value]).value, true
	}
	ele := c.lruList.PushFront(&entry[Key, Value]{key, value})
	c.cache[key] = ele
	if c.lruList.Len() > c.capacity {
		c.removeOldest()
	}
	return value, false
}

func (c *Cache[Key, Value]) Add(key Key, value Value) {
	if c.cache == nil {
		c.cache = make(map[Key]*list.Element)
		c.lruList = list.New()
	}
	if ee, ok := c.cache[key]; ok {
		c.lruList.MoveToFront(ee)
		ee.Value.(*entry[Key, Value]).value = value
		return
	}
	ele := c.lruList.PushFront(&entry[Key, Value]{key, value})
	c.cache[key] = ele
	if c.lruList.Len() > c.capacity {
		c.removeOldest()
	}
}

func (c *Cache[Key, Value]) Get(key Key) (value Value, ok bool) {
	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		c.lruList.MoveToFront(ele)
		return ele.Value.(*entry[Key, Value]).value, true
	}
	return
}

// Contain will check if a key is in the cache, but not modify the list
func (c *Cache[Key, Value]) Contain(key Key) bool {
	if c.cache == nil {
		return false
	}
	_, ok := c.cache[key]
	return ok
}

// Peek will return the key value but not modify the list
func (c *Cache[Key, Value]) Peek(key Key) (value Value, ok bool) {
	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		return ele.Value.(*entry[Key, Value]).value, true
	}
	return
}

// Keys returns a slice of all keys, from oldest to newest
func (c *Cache[Key, Value]) Keys() []Key {
	keys := make([]Key, len(c.cache))
	i := 0
	for ele := c.lruList.Back(); ele != nil; ele = ele.Prev() {
		keys[i] = ele.Value.(*entry[Key, Value]).key
		i++
	}
	return keys
}

// Values returns a slice of all values, from oldest to newest
func (c *Cache[Key, Value]) Values() []Value {
	values := make([]Value, len(c.cache))
	i := 0
	for ele := c.lruList.Back(); ele != nil; ele = ele.Prev() {
		values[i] = ele.Value.(*entry[Key, Value]).value
		i++
	}
	return values
}

func (c *Cache[Key, Value]) Remove(key Key) {
	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		c.removeElement(ele)
	}
}

func (c *Cache[Key, Value]) removeOldest() {
	if c.cache == nil {
		return
	}
	ele := c.lruList.Back()
	if ele != nil {
		c.removeElement(ele)
	}
}

func (c *Cache[Key, Value]) removeElement(e *list.Element) {
	c.lruList.Remove(e)
	kv := e.Value.(*entry[Key, Value])
	delete(c.cache, kv.key)
}

func (c *Cache[Key, Value]) Len() int {
	if c.cache == nil {
		return 0
	}
	return c.lruList.Len()
}

func (c *Cache[Key, Value]) Clear() {
	c.lruList = nil
	c.cache = nil
}
