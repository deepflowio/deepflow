package lru

import (
	"sync"

	"gitlab.x.lan/yunshan/droplet-libs/hmap/keyhash"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

type u64LRUNode struct {
	key   uint64
	value interface{}

	hashListNext int32 // 表示节点所在冲突链的下一个节点的 buffer 数组下标，-1 表示不存在
	hashListPrev int32 // 表示节点所在冲突链的上一个节点的 buffer 数组下标，-1 表示不存在
	timeListNext int32 // 时间链表，含义与冲突链类似
	timeListPrev int32 // 时间链表，含义与冲突链类似
}

var blankU64LRUNodeForInit u64LRUNode

type u64LRUNodeBlock []u64LRUNode

var u64LRUNodeBlockPool = sync.Pool{New: func() interface{} {
	return u64LRUNodeBlock(make([]u64LRUNode, _BLOCK_SIZE))
}}

// 注意：不是线程安全的
type U64LRU struct {
	utils.Closable

	ringBuffer       []u64LRUNodeBlock // 存储Map节点，以矩阵环的方式组织，提升内存申请释放效率
	bufferStartIndex int32             // ringBuffer中的开始下标（二维矩阵下标），闭区间
	bufferEndIndex   int32             // ringBuffer中的结束下标（二维矩阵下标），开区间

	hashSlots    int32  // 上取整至2^N，哈希桶个数
	hashSlotBits uint32 // hashSlots中低位连续0比特个数

	hashSlotHead []int32 // 哈希桶，hashSlotHead[i] 表示哈希值为 i 的冲突链的第一个节点为 buffer[[ hashSlotHead[i] ]]
	timeListHead int32
	timeListTail int32

	capacity int // 最大容纳的Flow个数
	size     int // 当前容纳的Flow个数
	maxScan  int
}

func (m *U64LRU) Size() int {
	return m.size
}

func (m *U64LRU) incIndex(index int32) int32 {
	index++
	if index>>_BLOCK_SIZE_BITS >= int32(len(m.ringBuffer)) {
		return 0
	}
	return index
}

func (m *U64LRU) decIndex(index int32) int32 {
	if index <= 0 {
		return int32(len(m.ringBuffer)<<_BLOCK_SIZE_BITS) - 1
	}
	return index - 1
}

func (m *U64LRU) getNode(index int32) *u64LRUNode {
	return &m.ringBuffer[index>>_BLOCK_SIZE_BITS][index&_BLOCK_SIZE_MASK]
}

func (m *U64LRU) pushNodeToHashList(node *u64LRUNode, nodeIndex int32, hash int32) {
	node.hashListNext = m.hashSlotHead[hash]
	node.hashListPrev = -1
	if node.hashListNext != -1 {
		m.getNode(node.hashListNext).hashListPrev = nodeIndex
	}
	m.hashSlotHead[hash] = nodeIndex
}

func (m *U64LRU) pushNodeToTimeList(node *u64LRUNode, nodeIndex int32) {
	node.timeListNext = m.timeListHead
	node.timeListPrev = -1
	if node.timeListNext != -1 {
		m.getNode(node.timeListNext).timeListPrev = nodeIndex
	}
	m.timeListHead = nodeIndex
	if m.timeListTail == -1 {
		m.timeListTail = nodeIndex
	}
}

func (m *U64LRU) removeNodeFromHashList(node *u64LRUNode, newNext, newPrev int32) {
	if node.hashListPrev != -1 {
		prevNode := m.getNode(node.hashListPrev)
		prevNode.hashListNext = newNext
	} else {
		m.hashSlotHead[m.compressHash(node.key)] = newNext
	}

	if node.hashListNext != -1 {
		nextNode := m.getNode(node.hashListNext)
		nextNode.hashListPrev = newPrev
	}
}

func (m *U64LRU) removeNodeFromTimeList(node *u64LRUNode, newNext, newPrev int32) {
	if node.timeListPrev != -1 {
		prevNode := m.getNode(node.timeListPrev)
		prevNode.timeListNext = newNext
	} else {
		m.timeListHead = newNext
	}

	if node.timeListNext != -1 {
		nextNode := m.getNode(node.timeListNext)
		nextNode.timeListPrev = newPrev
	} else {
		m.timeListTail = newPrev
	}
}

func (m *U64LRU) removeNode(node *u64LRUNode, nodeIndex int32) {
	// 从哈希链表、时间链表中删除
	m.removeNodeFromHashList(node, node.hashListNext, node.hashListPrev)
	m.removeNodeFromTimeList(node, node.timeListNext, node.timeListPrev)

	// 将节点交换至buffer头部
	if nodeIndex != m.bufferStartIndex {
		firstNode := m.getNode(m.bufferStartIndex)
		// 将firstNode内容拷贝至node
		*node = *firstNode
		// 修改firstNode在哈希链、时间链的上下游指向node
		m.removeNodeFromHashList(firstNode, nodeIndex, nodeIndex)
		m.removeNodeFromTimeList(firstNode, nodeIndex, nodeIndex)
		// 将firstNode初始化
		*firstNode = blankU64LRUNodeForInit
	} else {
		*node = blankU64LRUNodeForInit
	}

	// 释放头部节点
	if m.bufferStartIndex&_BLOCK_SIZE_MASK == _BLOCK_SIZE_MASK {
		u64LRUNodeBlockPool.Put(m.ringBuffer[m.bufferStartIndex>>_BLOCK_SIZE_BITS])
		m.ringBuffer[m.bufferStartIndex>>_BLOCK_SIZE_BITS] = nil
	}
	m.bufferStartIndex = m.incIndex(m.bufferStartIndex)

	m.size--
}

func (m *U64LRU) updateNode(node *u64LRUNode, nodeIndex int32, value interface{}) {
	if nodeIndex != m.timeListHead {
		// 从时间链表中删除
		m.removeNodeFromTimeList(node, node.timeListNext, node.timeListPrev)
		// 插入时间链表头部
		m.pushNodeToTimeList(node, nodeIndex)
	}

	node.value = value
}

func (m *U64LRU) newNode(key uint64, value interface{}) {
	// buffer空间检查
	if m.size >= m.capacity {
		node := m.getNode(m.timeListTail)
		m.removeNode(node, m.timeListTail)
	}
	row := m.bufferEndIndex >> _BLOCK_SIZE_BITS
	col := m.bufferEndIndex & _BLOCK_SIZE_MASK
	if m.ringBuffer[row] == nil {
		m.ringBuffer[row] = u64LRUNodeBlockPool.Get().(u64LRUNodeBlock)
	}
	node := &m.ringBuffer[row][col]
	m.size++

	// 新节点加入哈希链
	m.pushNodeToHashList(node, m.bufferEndIndex, m.compressHash(key))
	// 新节点加入时间链
	m.pushNodeToTimeList(node, m.bufferEndIndex)
	// 更新key、value
	node.key = key
	node.value = value

	// 更新buffer信息
	m.bufferEndIndex = m.incIndex(m.bufferEndIndex)
}

func (m *U64LRU) GetCounter() interface{} {
	counter := &Counter{m.maxScan, m.size}
	m.maxScan = 0
	return counter
}

func (m *U64LRU) Add(key uint64, value interface{}) {
	for hashListNext := m.hashSlotHead[m.compressHash(key)]; hashListNext != -1; {
		node := m.getNode(hashListNext)
		if node.key == key {
			m.updateNode(node, hashListNext, value)
			return
		}
		hashListNext = node.hashListNext
	}
	m.newNode(key, value)
}

func (m *U64LRU) Remove(key uint64) {
	for hashListNext := m.hashSlotHead[m.compressHash(key)]; hashListNext != -1; {
		node := m.getNode(hashListNext)
		if node.key == key {
			m.removeNode(node, hashListNext)
			return
		}
		hashListNext = node.hashListNext
	}
}

func (m *U64LRU) Get(key uint64, peek bool) (interface{}, bool) {
	maxScan := 0
	for hashListNext := m.hashSlotHead[m.compressHash(key)]; hashListNext != -1; {
		node := m.getNode(hashListNext)
		maxScan++
		if node.key == key {
			if !peek {
				m.updateNode(node, hashListNext, node.value)
			}
			if maxScan > m.maxScan {
				m.maxScan = maxScan
			}
			return node.value, true
		}
		hashListNext = node.hashListNext
	}
	if maxScan > m.maxScan {
		m.maxScan = maxScan
	}
	return nil, false
}

func (m *U64LRU) Walk(callback func(key uint64, value interface{})) {
	for i := m.timeListHead; i != -1; {
		node := m.getNode(i)
		callback(node.key, node.value)
		i = node.timeListNext
	}
}

func (m *U64LRU) Clear() {
	for i := range m.ringBuffer {
		if m.ringBuffer[i] != nil {
			for j := 0; j < len(m.ringBuffer[i]); j++ {
				m.ringBuffer[i][j].value = nil
			}
			u64LRUNodeBlockPool.Put(m.ringBuffer[i])
			m.ringBuffer[i] = nil
		}
	}
	m.bufferStartIndex = 0
	m.bufferEndIndex = 0

	for i := range m.hashSlotHead {
		m.hashSlotHead[i] = -1
	}
	m.timeListHead = -1
	m.timeListTail = -1

	m.size = 0
}

func (m *U64LRU) compressHash(hash uint64) int32 {
	return keyhash.Jenkins(hash) & (m.hashSlots - 1)
}

func NewU64LRU(module string, hashSlots, capacity int, opts ...stats.OptionStatTags) *U64LRU {
	hashSlots, hashSlotBits := minPowerOfTwo(hashSlots)

	m := &U64LRU{
		ringBuffer:   make([]u64LRUNodeBlock, (capacity+_BLOCK_SIZE)/_BLOCK_SIZE+1),
		hashSlots:    int32(hashSlots),
		hashSlotBits: uint32(hashSlotBits),
		hashSlotHead: make([]int32, hashSlots),
		timeListHead: -1,
		timeListTail: -1,
		capacity:     capacity,
	}

	for i := 0; i < len(m.hashSlotHead); i++ {
		m.hashSlotHead[i] = -1
	}
	statOptions := []stats.Option{stats.OptionStatTags{"module": module}}
	for _, opt := range opts {
		statOptions = append(statOptions, opt)
	}
	stats.RegisterCountable("lru", m, statOptions...)

	return m
}
