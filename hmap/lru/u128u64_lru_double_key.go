package lru

import (
	"sync"

	"gitlab.x.lan/yunshan/droplet-libs/hmap/keyhash"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
)

type u128u64DoubleKeyLRUNode struct {
	longKey0 uint64
	longKey1 uint64
	shortKey uint64
	value    interface{}

	hashListNext int32 // 表示节点所在冲突链的下一个节点的 buffer 数组下标，-1 表示不存在
	hashListPrev int32 // 表示节点所在冲突链的上一个节点的 buffer 数组下标，-1 表示不存在

	relationHashListNext int32 // 用于维护shortKey与longKey之间的关系，表示节点所在冲突链的下一个节点的 buffer 数组下标，-1 表示不存在
	relationHashListPrev int32 // 用于维护shortKey与longKey之间的关系，表示节点所在冲突链的上一个节点的 buffer 数组下标，-1 表示不存在

	timeListNext int32 // 时间链表，含义与冲突链类似
	timeListPrev int32 // 时间链表，含义与冲突链类似
}

var blankU128U64DoubleKeyLRUNodeForInit u128u64DoubleKeyLRUNode

type u128u64DoubleKeyLRUNodeBlock []u128u64DoubleKeyLRUNode

var u128u64DoubleKeyLRUNodeBlockPool = sync.Pool{New: func() interface{} {
	return u128u64DoubleKeyLRUNodeBlock(make([]u128u64DoubleKeyLRUNode, _BLOCK_SIZE))
}}

// 注意：不是线程安全的
type U128U64DoubleKeyLRU struct {
	utils.Closable

	ringBuffer       []u128u64DoubleKeyLRUNodeBlock // 存储Map节点，以矩阵环的方式组织，提升内存申请释放效率
	bufferStartIndex int32                          // ringBuffer中的开始下标（二维矩阵下标），闭区间
	bufferEndIndex   int32                          // ringBuffer中的结束下标（二维矩阵下标），开区间

	hashSlots    int32   // 上取整至2^N，哈希桶个数
	hashSlotBits uint32  // hashSlots中低位连续0比特个数
	hashSlotHead []int32 // 哈希桶，hashSlotHead[i] 表示哈希值为 i 的冲突链的第一个节点为 buffer[[ hashSlotHead[i] ]]

	relationHashSlots    int32 // 上取整至2^N，哈希桶个数
	relationHashSlotBits uint32
	relationHashSlotHead []int32 // 哈希桶，relationHashSlotHead[i] 表示shortKey为 i 的第一个节点为 buffer[[ relationHashSlotHead[i] ]]

	timeListHead int32
	timeListTail int32

	capacity          int
	size              int
	maxScan           int
	maxScanByShortKey int
	maxDelByshortKey  int // 当前通过shortKey删除的含有最多的成员数值
}

func (m *U128U64DoubleKeyLRU) NoStats() *U128U64DoubleKeyLRU {
	m.Close()
	return m
}

func (m *U128U64DoubleKeyLRU) Size() int {
	return m.size
}

func (m *U128U64DoubleKeyLRU) incIndex(index int32) int32 {
	index++
	if index>>_BLOCK_SIZE_BITS >= int32(len(m.ringBuffer)) {
		return 0
	}
	return index
}

func (m *U128U64DoubleKeyLRU) decIndex(index int32) int32 {
	if index <= 0 {
		return int32(len(m.ringBuffer)<<_BLOCK_SIZE_BITS) - 1
	}
	return index - 1
}

func (m *U128U64DoubleKeyLRU) getNode(index int32) *u128u64DoubleKeyLRUNode {
	return &m.ringBuffer[index>>_BLOCK_SIZE_BITS][index&_BLOCK_SIZE_MASK]
}

func (m *U128U64DoubleKeyLRU) pushNodeToHashList(node *u128u64DoubleKeyLRUNode, nodeIndex int32, hash int32) {
	node.hashListNext = m.hashSlotHead[hash]
	node.hashListPrev = -1
	if node.hashListNext != -1 {
		m.getNode(node.hashListNext).hashListPrev = nodeIndex
	}
	m.hashSlotHead[hash] = nodeIndex
}

func (m *U128U64DoubleKeyLRU) pushNodeToRelationHashList(node *u128u64DoubleKeyLRUNode, nodeIndex int32, hash int32) {
	node.relationHashListNext = m.relationHashSlotHead[hash]
	node.relationHashListPrev = -1
	if node.relationHashListNext != -1 {
		m.getNode(node.relationHashListNext).relationHashListPrev = nodeIndex
	}
	m.relationHashSlotHead[hash] = nodeIndex
}

func (m *U128U64DoubleKeyLRU) pushNodeToTimeList(node *u128u64DoubleKeyLRUNode, nodeIndex int32) {
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

func (m *U128U64DoubleKeyLRU) removeNodeFromHashList(node *u128u64DoubleKeyLRUNode, newNext, newPrev int32) {
	if node.hashListPrev != -1 {
		prevNode := m.getNode(node.hashListPrev)
		prevNode.hashListNext = newNext
	} else {
		m.hashSlotHead[m.compressHash(node.longKey0, node.longKey1)] = newNext
	}

	if node.hashListNext != -1 {
		nextNode := m.getNode(node.hashListNext)
		nextNode.hashListPrev = newPrev
	}
}

func (m *U128U64DoubleKeyLRU) removeNodeFromRelationHashList(node *u128u64DoubleKeyLRUNode, newNext, newPrev int32) {
	if node.relationHashListPrev != -1 {
		prevNode := m.getNode(node.relationHashListPrev)
		prevNode.relationHashListNext = newNext
	} else {
		m.relationHashSlotHead[m.compressRelationHash(node.shortKey)] = newNext
	}

	if node.relationHashListNext != -1 {
		nextNode := m.getNode(node.relationHashListNext)
		nextNode.relationHashListPrev = newPrev
	}
}

func (m *U128U64DoubleKeyLRU) removeNodeFromTimeList(node *u128u64DoubleKeyLRUNode, newNext, newPrev int32) {
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

// 删除指定node，当外层通过longKey进行删除时，不关心返回值，需要注意的是当外层通过shortKey进行删除时，删除的节点的
// 下一个关系节点(即本node的relationHashListNext)是存储单元ringbuffer当前的第一个有值元素时，返回本node的index
// 以确保下一个关系节点成功被删除
func (m *U128U64DoubleKeyLRU) removeNode(node *u128u64DoubleKeyLRUNode, nodeIndex int32) int32 {
	// 从哈希链表、关系哈希链表、时间链表中删除
	m.removeNodeFromHashList(node, node.hashListNext, node.hashListPrev)
	m.removeNodeFromRelationHashList(node, node.relationHashListNext, node.relationHashListPrev)
	m.removeNodeFromTimeList(node, node.timeListNext, node.timeListPrev)

	removeNodeNext := node.relationHashListNext
	bufferStartIndex := m.bufferStartIndex

	// 将节点交换至buffer头部
	if nodeIndex != m.bufferStartIndex {
		firstNode := m.getNode(m.bufferStartIndex)
		// 将firstNode内容拷贝至node
		*node = *firstNode
		// 修改firstNode在哈希链、关系哈希链、时间链的上下游指向node
		m.removeNodeFromHashList(firstNode, nodeIndex, nodeIndex)
		m.removeNodeFromRelationHashList(firstNode, nodeIndex, nodeIndex)
		m.removeNodeFromTimeList(firstNode, nodeIndex, nodeIndex)
		// 将firstNode初始化
		*firstNode = blankU128U64DoubleKeyLRUNodeForInit
	} else {
		*node = blankU128U64DoubleKeyLRUNodeForInit
	}

	// 释放头部节点
	if m.bufferStartIndex&_BLOCK_SIZE_MASK == _BLOCK_SIZE_MASK {
		u128u64DoubleKeyLRUNodeBlockPool.Put(m.ringBuffer[m.bufferStartIndex>>_BLOCK_SIZE_BITS])
		m.ringBuffer[m.bufferStartIndex>>_BLOCK_SIZE_BITS] = nil
	}
	m.bufferStartIndex = m.incIndex(m.bufferStartIndex)

	m.size--

	if removeNodeNext == bufferStartIndex {
		return nodeIndex
	}
	return -1
}

func (m *U128U64DoubleKeyLRU) updateNode(node *u128u64DoubleKeyLRUNode, nodeIndex int32, value interface{}) {
	if nodeIndex != m.timeListHead {
		// 从时间链表中删除
		m.removeNodeFromTimeList(node, node.timeListNext, node.timeListPrev)
		// 插入时间链表头部
		m.pushNodeToTimeList(node, nodeIndex)
	}

	node.value = value
}

func (m *U128U64DoubleKeyLRU) newNode(longKey0, longKey1, shortKey uint64, value interface{}, longKeyHash int32) {
	// buffer空间检查
	if m.size >= m.capacity {
		node := m.getNode(m.timeListTail)
		m.removeNode(node, m.timeListTail)
	}
	row := m.bufferEndIndex >> _BLOCK_SIZE_BITS
	col := m.bufferEndIndex & _BLOCK_SIZE_MASK
	if m.ringBuffer[row] == nil {
		m.ringBuffer[row] = u128u64DoubleKeyLRUNodeBlockPool.Get().(u128u64DoubleKeyLRUNodeBlock)
	}
	node := &m.ringBuffer[row][col]
	m.size++

	// 新节点加入哈希链
	m.pushNodeToHashList(node, m.bufferEndIndex, longKeyHash)

	// 新节点加入关系链
	m.pushNodeToRelationHashList(node, m.bufferEndIndex, m.compressRelationHash(shortKey))

	// 新节点加入时间链
	m.pushNodeToTimeList(node, m.bufferEndIndex)

	// 更新key、shortKey、value
	node.longKey0 = longKey0
	node.longKey1 = longKey1
	node.shortKey = shortKey
	node.value = value

	// 更新buffer信息
	m.bufferEndIndex = m.incIndex(m.bufferEndIndex)
}

func (m *U128U64DoubleKeyLRU) GetCounter() interface{} {
	counter := &DoubleKeyLRUCounter{m.maxScan, m.maxScanByShortKey, m.size, m.maxDelByshortKey}
	m.maxScan = 0
	m.maxScanByShortKey = 0
	m.maxDelByshortKey = 0
	return counter
}

// 通过longKey进行添加
func (m *U128U64DoubleKeyLRU) Add(longKey0, longKey1, shortKey uint64, value interface{}) {
	longKeyHash := m.compressHash(longKey0, longKey1)
	for hashListNext := m.hashSlotHead[longKeyHash]; hashListNext != -1; {
		node := m.getNode(hashListNext)
		if node.longKey0 == longKey0 && node.longKey1 == longKey1 {
			m.updateNode(node, hashListNext, value)
			return
		}
		hashListNext = node.hashListNext
	}
	m.newNode(longKey0, longKey1, shortKey, value, longKeyHash)
}

// 通过shortKey进行添加
func (m *U128U64DoubleKeyLRU) AddByShortKey(longKey0s, longKey1s []uint64, shortKey uint64, values []interface{}) {
	if len(longKey0s) != len(longKey1s) && len(longKey0s) != len(values) {
		return
	}

	for i := range longKey0s {
		m.Add(longKey0s[i], longKey1s[i], shortKey, values[i])
	}
}

// 通过longKey进行删除
func (m *U128U64DoubleKeyLRU) Remove(longKey0, longKey1 uint64) {
	for hashListNext := m.hashSlotHead[m.compressHash(longKey0, longKey1)]; hashListNext != -1; {
		node := m.getNode(hashListNext)
		if node.longKey0 == longKey0 && node.longKey1 == longKey1 {
			m.removeNode(node, hashListNext)
			return
		}
		hashListNext = node.hashListNext
	}
}

// 通过shortKey进行删除
func (m *U128U64DoubleKeyLRU) RemoveByShortKey(shortKey uint64) int {
	bakHashListNext := int32(0)
	delCount := 0
	var node *u128u64DoubleKeyLRUNode

	for relationHashListNext := m.relationHashSlotHead[m.compressRelationHash(shortKey)]; relationHashListNext != -1; {
		bakHashListNext = relationHashListNext
		node = m.getNode(relationHashListNext)
		relationHashListNext = node.relationHashListNext

		if node.shortKey == shortKey {
			nextNodeIndex := m.removeNode(node, bakHashListNext)
			if nextNodeIndex != -1 {
				relationHashListNext = nextNodeIndex
			}
			delCount++
		}
	}

	if m.maxDelByshortKey < delCount {
		m.maxDelByshortKey = delCount
	}
	return delCount
}

func (m *U128U64DoubleKeyLRU) Get(longKey0, longKey1 uint64, peek bool) (interface{}, bool) {
	maxScan := 0
	for hashListNext := m.hashSlotHead[m.compressHash(longKey0, longKey1)]; hashListNext != -1; {
		node := m.getNode(hashListNext)
		maxScan++
		if node.longKey0 == longKey0 && node.longKey1 == longKey1 {
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

func (m *U128U64DoubleKeyLRU) PeekByShortKey(shortKey uint64) ([]interface{}, bool) {
	maxScan := 0
	values := []interface{}{}

	for relationHashListNext := m.relationHashSlotHead[m.compressRelationHash(shortKey)]; relationHashListNext != -1; {
		node := m.getNode(relationHashListNext)
		maxScan++
		if node.shortKey == shortKey {
			values = append(values, node.value)
		}
		relationHashListNext = node.relationHashListNext
	}
	if maxScan > m.maxScanByShortKey {
		m.maxScanByShortKey = maxScan
	}
	if len(values) > 0 {
		return values, true
	}
	return nil, false
}

func (m *U128U64DoubleKeyLRU) Walk(callback func(longKey0, longKey1 uint64, value interface{})) {
	for i := m.timeListHead; i != -1; {
		node := m.getNode(i)
		callback(node.longKey0, node.longKey1, node.value)
		i = node.timeListNext
	}
}

func (m *U128U64DoubleKeyLRU) Clear() {
	for i := range m.ringBuffer {
		if m.ringBuffer[i] != nil {
			for j := 0; j < len(m.ringBuffer[i]); j++ {
				m.ringBuffer[i][j].value = nil
			}
			u128u64DoubleKeyLRUNodeBlockPool.Put(m.ringBuffer[i])
			m.ringBuffer[i] = nil
		}
	}
	m.bufferStartIndex = 0
	m.bufferEndIndex = 0

	for i := range m.hashSlotHead {
		m.hashSlotHead[i] = -1
	}

	for i := range m.relationHashSlotHead {
		m.relationHashSlotHead[i] = -1
	}

	m.timeListHead = -1
	m.timeListTail = -1

	m.size = 0
}

func (m *U128U64DoubleKeyLRU) compressHash(longKey0, longKey1 uint64) int32 {
	return keyhash.Jenkins128(longKey0, longKey1) & (m.hashSlots - 1)
}

func (m *U128U64DoubleKeyLRU) compressRelationHash(hash uint64) int32 {
	return keyhash.Jenkins(hash) & (m.relationHashSlots - 1)
}

func NewU128U64DoubleKeyLRU(module string, hashSlots, relationHashSlots, capacity int, opts ...stats.OptionStatTags) *U128U64DoubleKeyLRU {
	hashSlots, hashSlotBits := minPowerOfTwo(hashSlots)
	relationHashSlots, relationHashSlotBits := minPowerOfTwo(relationHashSlots)

	m := &U128U64DoubleKeyLRU{
		ringBuffer:   make([]u128u64DoubleKeyLRUNodeBlock, (capacity+_BLOCK_SIZE)/_BLOCK_SIZE+1),
		hashSlots:    int32(hashSlots),
		hashSlotBits: uint32(hashSlotBits),
		hashSlotHead: make([]int32, hashSlots),

		relationHashSlots:    int32(relationHashSlots),
		relationHashSlotBits: uint32(relationHashSlotBits),
		relationHashSlotHead: make([]int32, relationHashSlots),

		timeListHead: -1,
		timeListTail: -1,
		capacity:     capacity,
	}

	for i := 0; i < len(m.hashSlotHead); i++ {
		m.hashSlotHead[i] = -1
	}

	for j := 0; j < len(m.relationHashSlotHead); j++ {
		m.relationHashSlotHead[j] = -1
	}

	statOptions := []stats.Option{stats.OptionStatTags{"module": module}}
	for _, opt := range opts {
		statOptions = append(statOptions, opt)
	}
	stats.RegisterCountable("double_key_lru", m, statOptions...)

	return m
}
