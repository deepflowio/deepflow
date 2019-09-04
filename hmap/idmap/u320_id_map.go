package idmap

import (
	"bytes"
	"sync"
)

type u320IDMapNode struct {
	key   [40]byte
	hash  uint32 // key的hash值
	value uint32

	next int32 // 表示节点所在冲突链的下一个节点的 buffer 数组下标
	slot int32 // 记录 node 对应的哈希 slot ，为了避免 Clear 函数遍历整个 slotHead 数组
}

func (n *u320IDMapNode) equal(hash uint32, key []byte) bool {
	return n.hash == hash && bytes.Compare(n.key[:], key) == 0
}

var blankU320MapNodeForInit u320IDMapNode

type u320IDMapNodeBlock []u320IDMapNode

var u320IDMapNodeBlockPool = sync.Pool{New: func() interface{} {
	return u320IDMapNodeBlock(make([]u320IDMapNode, blockSize))
}}

// 注意：不是线程安全的
type U320IDMap struct {
	buffer []u320IDMapNodeBlock // 存储Map节点，以矩阵的方式组织，提升内存申请释放效率

	slotHead []int32 // 哈希桶，slotHead[i] 表示哈希值为 i 的冲突链的第一个节点为 buffer[[ slotHead[i]] ]]
	size     int     // buffer中存储的有效节点总数
	width    int     // 哈希桶中最大冲突链长度
}

func NewU320IDMap(hashSlots uint32) *U320IDMap {
	if hashSlots >= 1<<30 {
		panic("hashSlots is too large")
	}

	i := uint32(1)
	for i < hashSlots {
		i <<= 1
	}
	hashSlots = i

	m := &U320IDMap{
		buffer:   make([]u320IDMapNodeBlock, 0),
		slotHead: make([]int32, hashSlots),
	}

	for i := uint32(0); i < hashSlots; i++ {
		m.slotHead[i] = -1
	}
	return m
}

func (m *U320IDMap) Size() int {
	return m.size
}

func (m *U320IDMap) Width() int {
	return m.width
}

// 第一个返回值表示value，第二个返回值表示是否进行了Add。若key已存在，指定overwrite=true可覆写value。
func (m *U320IDMap) AddOrGet(key []byte, hash uint32, value uint32, overwrite bool) (uint32, bool) {
	slot := hash & uint32(len(m.slotHead)-1)
	head := m.slotHead[slot]

	width := 0
	next := head
	for next != -1 {
		width++
		node := &m.buffer[next>>blockSizeBits][next&blockSizeMask]
		if node.equal(hash, key) {
			if overwrite {
				node.value = value
			} else {
				value = node.value
			}
			return value, false
		}
		next = node.next
	}

	if m.size >= len(m.buffer)<<blockSizeBits { // expand
		m.buffer = append(m.buffer, u320IDMapNodeBlockPool.Get().(u320IDMapNodeBlock))
	}
	node := &m.buffer[m.size>>blockSizeBits][m.size&blockSizeMask]
	copy(node.key[:], key)
	node.hash = hash
	node.value = value
	node.next = head
	node.slot = int32(slot)

	m.slotHead[slot] = int32(m.size)
	m.size++

	if m.width < width+1 {
		m.width = width + 1
	}

	return value, true
}

func (m *U320IDMap) Get(key []byte, hash uint32) (uint32, bool) {
	slot := hash & uint32(len(m.slotHead)-1)
	head := m.slotHead[slot]

	next := head
	for next != -1 {
		node := &m.buffer[next>>blockSizeBits][next&blockSizeMask]
		if node.equal(hash, key) {
			return node.value, true
		}
		next = node.next
	}
	return 0, false
}

func (m *U320IDMap) Clear() {
	for i := 0; i < m.size; i += blockSize {
		for j := 0; j < blockSize && i+j < m.size; j++ {
			node := &m.buffer[i>>blockSizeBits][j]
			m.slotHead[node.slot] = -1
			*node = blankU320MapNodeForInit
		}
		u320IDMapNodeBlockPool.Put(m.buffer[i>>blockSizeBits])
		m.buffer[i>>blockSizeBits] = nil
	}

	m.buffer = m.buffer[:0]

	m.size = 0
	m.width = 0
}
