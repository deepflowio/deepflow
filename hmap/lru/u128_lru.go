package lru

import (
	"sync"

	"gitlab.x.lan/yunshan/droplet-libs/hmap/keyhash"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

type u128LRUNode struct {
	key0  uint64
	key1  uint64
	value interface{}

	hashListNext int32 // 表示节点所在冲突链的下一个节点的 buffer 数组下标，-1 表示不存在
	hashListPrev int32 // 表示节点所在冲突链的上一个节点的 buffer 数组下标，-1 表示不存在
	timeListNext int32 // 时间链表，含义与冲突链类似
	timeListPrev int32 // 时间链表，含义与冲突链类似

	hash int32
}

var blankU128LRUNodeForInit u128LRUNode

type u128LRUNodeBlock []u128LRUNode

var u128LRUNodeBlockPool = sync.Pool{New: func() interface{} {
	return u128LRUNodeBlock(make([]u128LRUNode, _BLOCK_SIZE))
}}

// 注意：不是线程安全的
type U128LRU struct {
	stats.Closable

	ringBuffer       []u128LRUNodeBlock // 存储Map节点，以矩阵环的方式组织，提升内存申请释放效率
	bufferStartIndex int32              // ringBuffer中的开始下标（二维矩阵下标），闭区间
	bufferEndIndex   int32              // ringBuffer中的结束下标（二维矩阵下标），开区间

	hashSlots    int32  // 上取整至2^N，哈希桶个数
	hashSlotBits uint32 // hashSlots中低位连续0比特个数

	hashSlotHead []int32 // 哈希桶，hashSlotHead[i] 表示哈希值为 i 的冲突链的第一个节点为 buffer[[ hashSlotHead[i] ]]
	timeListHead int32
	timeListTail int32

	capacity int // 最大容纳的Flow个数
	size     int // 当前容纳的Flow个数
	maxScan  int
}

func (m *U128LRU) Size() int {
	return m.size
}

func (m *U128LRU) incIndex(index int32) int32 {
	index++
	if index>>_BLOCK_SIZE_BITS >= int32(len(m.ringBuffer)) {
		return 0
	}
	return index
}

func (m *U128LRU) decIndex(index int32) int32 {
	if index <= 0 {
		return int32(len(m.ringBuffer)<<_BLOCK_SIZE_BITS) - 1
	}
	return index - 1
}

func (m *U128LRU) getNode(index int32) *u128LRUNode {
	return &m.ringBuffer[index>>_BLOCK_SIZE_BITS][index&_BLOCK_SIZE_MASK]
}

func (m *U128LRU) pushNodeToHashList(node *u128LRUNode, nodeIndex int32, hash int32) {
	node.hashListNext = m.hashSlotHead[hash]
	node.hashListPrev = -1
	if node.hashListNext != -1 {
		m.getNode(node.hashListNext).hashListPrev = nodeIndex
	}
	m.hashSlotHead[hash] = nodeIndex
}

func (m *U128LRU) pushNodeToTimeList(node *u128LRUNode, nodeIndex int32) {
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

func (m *U128LRU) removeNodeFromHashList(node *u128LRUNode, newNext, newPrev int32) {
	if node.hashListPrev != -1 {
		prevNode := m.getNode(node.hashListPrev)
		prevNode.hashListNext = newNext
	} else {
		m.hashSlotHead[node.hash] = newNext
	}

	if node.hashListNext != -1 {
		nextNode := m.getNode(node.hashListNext)
		nextNode.hashListPrev = newPrev
	}
}

func (m *U128LRU) removeNodeFromTimeList(node *u128LRUNode, newNext, newPrev int32) {
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

func (m *U128LRU) removeNode(node *u128LRUNode, nodeIndex int32) {
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
		*firstNode = blankU128LRUNodeForInit
	} else {
		*node = blankU128LRUNodeForInit
	}

	// 释放头部节点
	if m.bufferStartIndex&_BLOCK_SIZE_MASK == _BLOCK_SIZE_MASK {
		u128LRUNodeBlockPool.Put(m.ringBuffer[m.bufferStartIndex>>_BLOCK_SIZE_BITS])
		m.ringBuffer[m.bufferStartIndex>>_BLOCK_SIZE_BITS] = nil
	}
	m.bufferStartIndex = m.incIndex(m.bufferStartIndex)

	m.size--
}

func (m *U128LRU) updateNode(node *u128LRUNode, nodeIndex int32, value interface{}) {
	if nodeIndex != m.timeListHead {
		// 从时间链表中删除
		m.removeNodeFromTimeList(node, node.timeListNext, node.timeListPrev)
		// 插入时间链表头部
		m.pushNodeToTimeList(node, nodeIndex)
	}
	if nodeIndex != m.hashSlotHead[node.hash] {
		// 从hash链表中删除
		m.removeNodeFromHashList(node, node.hashListNext, node.hashListPrev)
		// 插入到hash链表头部
		m.pushNodeToHashList(node, nodeIndex, node.hash)
	}

	node.value = value
}

func (m *U128LRU) newNode(key0, key1 uint64, value interface{}, hash int32) {
	// buffer空间检查
	if m.size >= m.capacity {
		node := m.getNode(m.timeListTail)
		m.removeNode(node, m.timeListTail)
	}
	row := m.bufferEndIndex >> _BLOCK_SIZE_BITS
	col := m.bufferEndIndex & _BLOCK_SIZE_MASK
	if m.ringBuffer[row] == nil {
		m.ringBuffer[row] = u128LRUNodeBlockPool.Get().(u128LRUNodeBlock)
	}
	node := &m.ringBuffer[row][col]
	m.size++

	// 新节点加入哈希链
	m.pushNodeToHashList(node, m.bufferEndIndex, hash)
	// 新节点加入时间链
	m.pushNodeToTimeList(node, m.bufferEndIndex)
	// 更新key、value
	node.key0 = key0
	node.key1 = key1
	node.value = value
	node.hash = hash

	// 更新buffer信息
	m.bufferEndIndex = m.incIndex(m.bufferEndIndex)
}

func (m *U128LRU) GetCounter() interface{} {
	counter := &Counter{m.maxScan, m.size}
	m.maxScan = 0
	return counter
}

func (m *U128LRU) Add(key0, key1 uint64, value interface{}) {
	hash := m.compressHash(key0, key1)
	for hashListNext := m.hashSlotHead[hash]; hashListNext != -1; {
		node := m.getNode(hashListNext)
		if node.key0 == key0 && node.key1 == key1 {
			m.updateNode(node, hashListNext, value)
			return
		}
		hashListNext = node.hashListNext
	}
	m.newNode(key0, key1, value, hash)
}

func (m *U128LRU) Remove(key0, key1 uint64) {
	for hashListNext := m.hashSlotHead[m.compressHash(key0, key1)]; hashListNext != -1; {
		node := m.getNode(hashListNext)
		if node.key0 == key0 && node.key1 == key1 {
			m.removeNode(node, hashListNext)
			return
		}
		hashListNext = node.hashListNext
	}
}

func (m *U128LRU) Get(key0, key1 uint64, peek bool) (interface{}, bool) {
	maxScan := 0
	for hashListNext := m.hashSlotHead[m.compressHash(key0, key1)]; hashListNext != -1; {
		node := m.getNode(hashListNext)
		maxScan++
		if node.key0 == key0 && node.key1 == key1 {
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

func (m *U128LRU) Clear() {
	for i := range m.ringBuffer {
		if m.ringBuffer[i] != nil {
			for j := 0; j < len(m.ringBuffer[i]); j++ {
				m.ringBuffer[i][j].value = nil
			}
			u128LRUNodeBlockPool.Put(m.ringBuffer[i])
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

func (m *U128LRU) compressHash(key0, key1 uint64) int32 {
	return keyhash.Jenkins128(key0, key1) & (m.hashSlots - 1)
}

type walkCallback func(key0, key1 uint64, value interface{})

func (m *U128LRU) Walk(callback walkCallback) {
	for i := m.timeListHead; i != -1; {
		node := m.getNode(i)
		callback(node.key0, node.key1, node.value)
		i = node.timeListNext
	}
}

func NewU128LRU(module string, hashSlots, capacity int, opts ...stats.OptionStatTags) *U128LRU {
	hashSlots, hashSlotBits := minPowerOfTwo(hashSlots)

	m := &U128LRU{
		ringBuffer:   make([]u128LRUNodeBlock, (capacity+_BLOCK_SIZE)/_BLOCK_SIZE+1),
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
