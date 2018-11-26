package utils

import (
	"container/list"
)

type LRUCache struct {
	capacity int
	lruList  *list.List
	cache    map[interface{}]*list.Element
}

type entry struct {
	key   interface{}
	value interface{}
}

func NewLRUCache(maxEntries int) *LRUCache {
	return &LRUCache{
		capacity: maxEntries,
		lruList:  list.New(),
		cache:    make(map[interface{}]*list.Element),
	}
}

func (c *LRUCache) Add(key interface{}, value interface{}) {
	if c.cache == nil {
		c.cache = make(map[interface{}]*list.Element)
		c.lruList = list.New()
	}
	if ee, ok := c.cache[key]; ok {
		c.lruList.MoveToFront(ee)
		ee.Value.(*entry).value = value
		return
	}
	ele := c.lruList.PushFront(&entry{key, value})
	c.cache[key] = ele
	if c.lruList.Len() > c.capacity {
		c.removeOldest()
	}
}

func (c *LRUCache) Get(key interface{}) (value interface{}, ok bool) {
	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		c.lruList.MoveToFront(ele)
		return ele.Value.(*entry).value, true
	}
	return
}

// Contain will check if a key is in the cache, but not modify the list
func (c *LRUCache) Contain(key interface{}) bool {
	if c.cache == nil {
		return false
	}
	_, ok := c.cache[key]
	return ok
}

// Peek will return the key value but not modify the list
func (c *LRUCache) Peek(key interface{}) (value interface{}, ok bool) {
	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		return ele.Value.(*entry).value, true
	}
	return
}

// Keys returns a slice of all keys, from oldest to newest
func (c *LRUCache) Keys() []interface{} {
	keys := make([]interface{}, len(c.cache))
	i := 0
	for ele := c.lruList.Back(); ele != nil; ele = ele.Prev() {
		keys[i] = ele.Value.(*entry).key
		i++
	}
	return keys
}

// Values returns a slice of all values, from oldest to newest
func (c *LRUCache) Values() []interface{} {
	values := make([]interface{}, len(c.cache))
	i := 0
	for ele := c.lruList.Back(); ele != nil; ele = ele.Prev() {
		values[i] = ele.Value.(*entry).value
		i++
	}
	return values
}

func (c *LRUCache) Remove(key interface{}) {
	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		c.removeElement(ele)
	}
}

func (c *LRUCache) removeOldest() {
	if c.cache == nil {
		return
	}
	ele := c.lruList.Back()
	if ele != nil {
		c.removeElement(ele)
	}
}

func (c *LRUCache) removeElement(e *list.Element) {
	c.lruList.Remove(e)
	kv := e.Value.(*entry)
	delete(c.cache, kv.key)
}

func (c *LRUCache) Len() int {
	if c.cache == nil {
		return 0
	}
	return c.lruList.Len()
}

func (c *LRUCache) Clear() {
	c.lruList = nil
	c.cache = nil
}
