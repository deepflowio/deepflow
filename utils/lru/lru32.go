package utils

import (
	"container/list"
)

type LRU32Cache struct {
	capacity int
	lruList  *list.List
	cache    map[uint32]*list.Element
}

type entry32 struct {
	key   uint32
	value interface{}
}

func NewLRU32Cache(maxEntries int) *LRU32Cache {
	return &LRU32Cache{
		capacity: maxEntries,
		lruList:  list.New(),
		cache:    make(map[uint32]*list.Element),
	}
}

func (c *LRU32Cache) Add(key uint32, value interface{}) {
	if c.cache == nil {
		c.cache = make(map[uint32]*list.Element)
		c.lruList = list.New()
	}
	if ee, ok := c.cache[key]; ok {
		c.lruList.MoveToFront(ee)
		ee.Value.(*entry32).value = value
		return
	}
	ele := c.lruList.PushFront(&entry32{key, value})
	c.cache[key] = ele
	if c.lruList.Len() > c.capacity {
		c.removeOldest()
	}
}

func (c *LRU32Cache) Get(key uint32) (value interface{}, ok bool) {
	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		c.lruList.MoveToFront(ele)
		return ele.Value.(*entry32).value, true
	}
	return
}

// Contain will check if a key is in the cache, but not modify the list
func (c *LRU32Cache) Contain(key uint32) bool {
	if c.cache == nil {
		return false
	}
	_, ok := c.cache[key]
	return ok
}

// Peek will return the key value but not modify the list
func (c *LRU32Cache) Peek(key uint32) (value interface{}, ok bool) {
	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		return ele.Value.(*entry32).value, true
	}
	return
}

// Keys returns a slice of all keys, from oldest to newest
func (c *LRU32Cache) Keys() []uint32 {
	keys := make([]uint32, len(c.cache))
	i := 0
	for ele := c.lruList.Back(); ele != nil; ele = ele.Prev() {
		keys[i] = ele.Value.(*entry32).key
		i++
	}
	return keys
}

// Values returns a slice of all values, from oldest to newest
func (c *LRU32Cache) Values() []interface{} {
	values := make([]interface{}, len(c.cache))
	i := 0
	for ele := c.lruList.Back(); ele != nil; ele = ele.Prev() {
		values[i] = ele.Value.(*entry32).value
		i++
	}
	return values
}

func (c *LRU32Cache) Remove(key uint32) {
	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		c.removeElement(ele)
	}
}

func (c *LRU32Cache) removeOldest() {
	if c.cache == nil {
		return
	}
	ele := c.lruList.Back()
	if ele != nil {
		c.removeElement(ele)
	}
}

func (c *LRU32Cache) removeElement(e *list.Element) {
	c.lruList.Remove(e)
	kv := e.Value.(*entry32)
	delete(c.cache, kv.key)
}

func (c *LRU32Cache) Len() int {
	if c.cache == nil {
		return 0
	}
	return c.lruList.Len()
}

func (c *LRU32Cache) Clear() {
	c.lruList = nil
	c.cache = nil
}
