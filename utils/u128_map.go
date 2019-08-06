package utils

import (
	"gitlab.x.lan/yunshan/droplet-libs/pool"
)

type mapNode struct {
	key0  uint64
	key1  uint64
	value uint32
}

var mapNodePool = pool.NewLockFreePool(func() interface{} {
	return new(mapNode)
})

func acquireMapNode() *mapNode {
	return mapNodePool.Get().(*mapNode)
}

func releaseMapNode(n *mapNode) {
	if n != nil {
		mapNodePool.Put(n)
	}
}

func (n *mapNode) equal(v *mapNode) bool {
	return n.key0 == v.key0 && n.key1 == v.key1
}

// 注意：不是线程安全的
type U128ToU32Map struct {
	buffer []*mapNode // 使用数组链表实现的冲突链，存储节点
	next   []int32    // 使用数组链表实现的冲突链，next[i] 表示 buffer[i] 所在链的下一个节点的 buffer 数组下标
	head   []int32    // 哈希表，head[i] 表示哈希值为 i 的冲突链的第一个节点为 buffer[head[i]]
	heads  []int32    // 顺次记录 buffer 中各个元素对应的哈希值在 head 中的下标，为了避免 Clear 函数遍历整个 head 数组
	size   int        // 数组链表中存储的节点总数
	width  int        // 最大冲突链长度

	node mapNode // 供Add和Find使用，避免内存申请
}

func NewU128ToU32Map(capacity uint32) *U128ToU32Map {
	if capacity >= 1<<30 {
		panic("capacity is too large")
	}

	i := uint32(1)
	for i < capacity {
		i <<= 1
	}
	capacity = i

	m := &U128ToU32Map{
		buffer: make([]*mapNode, capacity),
		next:   make([]int32, capacity),
		head:   make([]int32, capacity),
		heads:  make([]int32, capacity),
	}

	for i := uint32(0); i < capacity; i++ {
		m.next[i] = -1
		m.head[i] = -1
		m.heads[i] = -1
	}
	return m
}

func (m *U128ToU32Map) Size() int {
	return m.size
}

func (m *U128ToU32Map) Width() int {
	return m.width
}

// 第一个返回值表示value，第二个返回值表示是否进行了Add。若key已存在，指定overwrite=true可覆写value。
func (m *U128ToU32Map) AddOrGet(key0, key1 uint64, value uint32, overwrite bool) (uint32, bool) {
	node := &m.node
	node.key0 = key0
	node.key1 = key1
	node.value = value

	slot := (uint32(key0>>32) ^ uint32(key0) ^ uint32(key1>>32) ^ uint32(key1)) & uint32(len(m.head)-1)
	head := m.head[slot]

	width := 0
	next := head
	for next != -1 {
		width++
		if m.buffer[next].equal(node) {
			if overwrite {
				m.buffer[next].value = value
			} else {
				value = m.buffer[next].value
			}
			return value, false
		}
		next = m.next[next]
	}

	m.buffer[m.size] = acquireMapNode()
	*m.buffer[m.size] = *node
	m.next[m.size] = head
	m.heads[m.size] = int32(slot)
	m.head[slot] = int32(m.size)
	m.size++
	if m.width < width+1 {
		m.width = width + 1
	}

	return value, true
}

func (m *U128ToU32Map) Get(key0, key1 uint64) (uint32, bool) {
	node := &m.node
	node.key0 = key0
	node.key1 = key1

	slot := (uint32(key0>>32) ^ uint32(key0) ^ uint32(key1>>32) ^ uint32(key1)) & uint32(len(m.head)-1)
	head := m.head[slot]

	next := head
	for next != -1 {
		if m.buffer[next].equal(node) {
			return m.buffer[next].value, true
		}
		next = m.next[next]
	}
	return 0, false
}

func (m *U128ToU32Map) Clear() {
	for i := 0; i < m.size; i++ {
		releaseMapNode(m.buffer[i])
		m.buffer[i] = nil
		m.next[i] = -1
		m.head[m.heads[i]] = -1
		m.heads[i] = -1
	}
	m.size = 0
	m.width = 0
}
