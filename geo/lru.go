package geo

import (
	"container/list"
)

type Cache struct {
	capacity int
	lruList  *list.List
	cache    map[uint32]*list.Element
}

type entry struct {
	key   uint32
	value interface{}
}

func NewCache(maxEntries int) *Cache {
	return &Cache{
		capacity: maxEntries,
		lruList:  list.New(),
		cache:    make(map[uint32]*list.Element),
	}
}

func (c *Cache) Add(key uint32, value interface{}) {
	if c.cache == nil {
		c.cache = make(map[uint32]*list.Element)
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

func (c *Cache) Get(key uint32) (value interface{}, ok bool) {
	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		c.lruList.MoveToFront(ele)
		return ele.Value.(*entry).value, true
	}
	return
}

func (c *Cache) Remove(key uint32) {
	if c.cache == nil {
		return
	}
	if ele, hit := c.cache[key]; hit {
		c.removeElement(ele)
	}
}

func (c *Cache) removeOldest() {
	if c.cache == nil {
		return
	}
	ele := c.lruList.Back()
	if ele != nil {
		c.removeElement(ele)
	}
}

func (c *Cache) removeElement(e *list.Element) {
	c.lruList.Remove(e)
	kv := e.Value.(*entry)
	delete(c.cache, kv.key)
}

func (c *Cache) Len() int {
	if c.cache == nil {
		return 0
	}
	return c.lruList.Len()
}

func (c *Cache) Clear() {
	c.lruList = nil
	c.cache = nil
}
