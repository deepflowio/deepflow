/*
 * Copyright (c) 2022 Yunshan Networks
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
	"encoding/binary"
	"sync"
	"sync/atomic"

	"github.com/deepflowio/deepflow/server/libs/hmap"
	"github.com/deepflowio/deepflow/server/libs/hmap/keyhash"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

type u64DoubleKeyLRUNode struct {
	key      uint64
	shortKey uint64
	value    interface{}

	hashListNext int32 // 表示节点所在冲突链的下一个节点的 buffer 数组下标，-1 表示不存在
	hashListPrev int32 // 表示节点所在冲突链的上一个节点的 buffer 数组下标，-1 表示不存在

	relationHashListNext int32 // 用于维护shortKey与longKey之间的关系，表示节点所在冲突链的下一个节点的 buffer 数组下标，-1 表示不存在
	relationHashListPrev int32 // 用于维护shortKey与longKey之间的关系，表示节点所在冲突链的上一个节点的 buffer 数组下标，-1 表示不存在

	timeListNext int32 // 时间链表，含义与冲突链类似
	timeListPrev int32 // 时间链表，含义与冲突链类似
}

var blankU64DoubleKeyLRUNodeForInit u64DoubleKeyLRUNode

type u64DoubleKeyLRUNodeBlock []u64DoubleKeyLRUNode

var u64DoubleKeyLRUNodeBlockPool = sync.Pool{New: func() interface{} {
	return u64DoubleKeyLRUNodeBlock(make([]u64DoubleKeyLRUNode, _BLOCK_SIZE))
}}

// 注意：不是线程安全的
type U64DoubleKeyLRU struct {
	utils.Closable

	id string

	ringBuffer       []u64DoubleKeyLRUNodeBlock // 存储Map节点，以矩阵环的方式组织，提升内存申请释放效率
	bufferStartIndex int32                      // ringBuffer中的开始下标（二维矩阵下标），闭区间
	bufferEndIndex   int32                      // ringBuffer中的结束下标（二维矩阵下标），开区间

	hashSlots    int32   // 上取整至2^N，哈希桶个数
	hashSlotBits uint32  // hashSlots中低位连续0比特个数
	hashSlotHead []int32 // 哈希桶，hashSlotHead[i] 表示哈希值为 i 的冲突链的第一个节点为 buffer[[ hashSlotHead[i] ]]

	relationHashSlots    int32 // 上取整至2^N，哈希桶个数
	relationHashSlotBits uint32
	relationHashSlotHead []int32 // 哈希桶，relationHashSlotHead[i] 表示shortKey为 i 的第一个节点为 buffer[[ relationHashSlotHead[i] ]]

	timeListHead int32
	timeListTail int32

	capacity int
	size     int

	counter *DoubleKeyLRUCounter

	collisionChainDebugThreshold uint32       // scan宽度超过该值时保留冲突链信息，为0时不保存
	debugChain                   atomic.Value // 冲突链，类型为[]byte
	debugChainRead               uint32       // 冲突链是否已读，如果已读替换为新的 (atomic.Value无法清空)
}

func (m *U64DoubleKeyLRU) ID() string {
	return m.id
}

func (m *U64DoubleKeyLRU) KeySize() int {
	return 64 / 8
}

func (m *U64DoubleKeyLRU) NoStats() *U64DoubleKeyLRU {
	m.Close()
	return m
}

func (m *U64DoubleKeyLRU) Size() int {
	return m.size
}

func (m *U64DoubleKeyLRU) incIndex(index int32) int32 {
	index++
	if index>>_BLOCK_SIZE_BITS >= int32(len(m.ringBuffer)) {
		return 0
	}
	return index
}

func (m *U64DoubleKeyLRU) decIndex(index int32) int32 {
	if index <= 0 {
		return int32(len(m.ringBuffer)<<_BLOCK_SIZE_BITS) - 1
	}
	return index - 1
}

func (m *U64DoubleKeyLRU) getNode(index int32) *u64DoubleKeyLRUNode {
	return &m.ringBuffer[index>>_BLOCK_SIZE_BITS][index&_BLOCK_SIZE_MASK]
}

func (m *U64DoubleKeyLRU) pushNodeToHashList(node *u64DoubleKeyLRUNode, nodeIndex int32, hash int32) {
	node.hashListNext = m.hashSlotHead[hash]
	node.hashListPrev = -1
	if node.hashListNext != -1 {
		m.getNode(node.hashListNext).hashListPrev = nodeIndex
	}
	m.hashSlotHead[hash] = nodeIndex
}

func (m *U64DoubleKeyLRU) pushNodeToRelationHashList(node *u64DoubleKeyLRUNode, nodeIndex int32, hash int32) {
	node.relationHashListNext = m.relationHashSlotHead[hash]
	node.relationHashListPrev = -1
	if node.relationHashListNext != -1 {
		m.getNode(node.relationHashListNext).relationHashListPrev = nodeIndex
	}
	m.relationHashSlotHead[hash] = nodeIndex
}

func (m *U64DoubleKeyLRU) pushNodeToTimeList(node *u64DoubleKeyLRUNode, nodeIndex int32) {
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

func (m *U64DoubleKeyLRU) removeNodeFromHashList(node *u64DoubleKeyLRUNode, newNext, newPrev int32) {
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

func (m *U64DoubleKeyLRU) removeNodeFromRelationHashList(node *u64DoubleKeyLRUNode, newNext, newPrev int32) {
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

func (m *U64DoubleKeyLRU) removeNodeFromTimeList(node *u64DoubleKeyLRUNode, newNext, newPrev int32) {
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
func (m *U64DoubleKeyLRU) removeNode(node *u64DoubleKeyLRUNode, nodeIndex int32) int32 {
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
		*firstNode = blankU64DoubleKeyLRUNodeForInit
	} else {
		*node = blankU64DoubleKeyLRUNodeForInit
	}

	// 释放头部节点
	if m.bufferStartIndex&_BLOCK_SIZE_MASK == _BLOCK_SIZE_MASK {
		u64DoubleKeyLRUNodeBlockPool.Put(m.ringBuffer[m.bufferStartIndex>>_BLOCK_SIZE_BITS])
		m.ringBuffer[m.bufferStartIndex>>_BLOCK_SIZE_BITS] = nil
	}
	m.bufferStartIndex = m.incIndex(m.bufferStartIndex)

	m.size--

	if removeNodeNext == bufferStartIndex {
		return nodeIndex
	}
	return -1
}

func (m *U64DoubleKeyLRU) updateNode(node *u64DoubleKeyLRUNode, nodeIndex int32, value interface{}) {
	if nodeIndex != m.timeListHead {
		// 从时间链表中删除
		m.removeNodeFromTimeList(node, node.timeListNext, node.timeListPrev)
		// 插入时间链表头部
		m.pushNodeToTimeList(node, nodeIndex)
	}

	node.value = value
}

func (m *U64DoubleKeyLRU) newNode(key uint64, shortKey uint64, value interface{}) {
	// buffer空间检查
	if m.size >= m.capacity {
		node := m.getNode(m.timeListTail)
		m.removeNode(node, m.timeListTail)
	}
	row := m.bufferEndIndex >> _BLOCK_SIZE_BITS
	col := m.bufferEndIndex & _BLOCK_SIZE_MASK
	if m.ringBuffer[row] == nil {
		m.ringBuffer[row] = u64DoubleKeyLRUNodeBlockPool.Get().(u64DoubleKeyLRUNodeBlock)
	}
	node := &m.ringBuffer[row][col]
	m.size++

	// 新节点加入哈希链
	m.pushNodeToHashList(node, m.bufferEndIndex, m.compressHash(key))

	// 新节点加入关系链
	m.pushNodeToRelationHashList(node, m.bufferEndIndex, m.compressRelationHash(shortKey))

	// 新节点加入时间链
	m.pushNodeToTimeList(node, m.bufferEndIndex)

	// 更新key、shortKey、value
	node.key = key
	node.shortKey = shortKey
	node.value = value

	// 更新buffer信息
	m.bufferEndIndex = m.incIndex(m.bufferEndIndex)
}

func (m *U64DoubleKeyLRU) GetCounter() interface{} {
	var counter *DoubleKeyLRUCounter
	counter, m.counter = m.counter, &DoubleKeyLRUCounter{}
	if counter.scanTimes != 0 {
		counter.AvgScan = counter.totalScan / counter.scanTimes
	}
	counter.Size = m.size
	return counter
}

// 通过longKey进行添加
func (m *U64DoubleKeyLRU) Add(key uint64, shortKey uint64, value interface{}) {
	node, hashIndex := m.find(key, true)
	if node != nil {
		m.updateNode(node, hashIndex, value)
		return
	}
	m.newNode(key, shortKey, value)
}

// 通过shortKey进行添加
func (m *U64DoubleKeyLRU) AddByShortKey(keys []uint64, shortKey uint64, values []interface{}) {
	if len(keys) != len(values) {
		return
	}

	for i, key := range keys {
		m.Add(key, shortKey, values[i])
	}
}

// 通过longKey进行删除
func (m *U64DoubleKeyLRU) Remove(key uint64) {
	for hashListNext := m.hashSlotHead[m.compressHash(key)]; hashListNext != -1; {
		node := m.getNode(hashListNext)
		if node.key == key {
			m.removeNode(node, hashListNext)
			return
		}
		hashListNext = node.hashListNext
	}
}

// 通过shortKey进行删除
func (m *U64DoubleKeyLRU) RemoveByShortKey(key uint64) int {
	bakHashListNext := int32(0)
	delCount := 0
	maxScan := 0
	var node *u64DoubleKeyLRUNode

	for relationHashListNext := m.relationHashSlotHead[m.compressRelationHash(key)]; relationHashListNext != -1; {
		bakHashListNext = relationHashListNext
		node = m.getNode(relationHashListNext)
		relationHashListNext = node.relationHashListNext
		maxScan++

		if node.shortKey == key {
			nextNodeIndex := m.removeNode(node, bakHashListNext)
			if nextNodeIndex != -1 {
				relationHashListNext = nextNodeIndex
			}
			delCount++
		}
	}

	if maxScan > m.counter.MaxShortBucket {
		m.counter.MaxShortBucket = maxScan
	}
	if m.counter.MaxLongBucket < delCount {
		m.counter.MaxLongBucket = delCount
	}
	return delCount
}

func (m *U64DoubleKeyLRU) find(key uint64, isAdd bool) (*u64DoubleKeyLRUNode, int32) {
	m.counter.scanTimes++
	width := 0
	slot := m.compressHash(key)
	for hashListNext := m.hashSlotHead[slot]; hashListNext != -1; {
		width++
		node := m.getNode(hashListNext)
		if node.key == key {
			m.counter.totalScan += width
			if width > m.counter.Max {
				m.counter.Max = width
			}

			if atomic.LoadUint32(&m.debugChainRead) == 1 {
				// 已读，构造新的chain
				if threshold := int(atomic.LoadUint32(&m.collisionChainDebugThreshold)); threshold > 0 && width >= threshold {
					chain := make([]byte, m.KeySize()*width)
					m.generateCollisionChainInLongKey(chain, slot)
					m.debugChain.Store(chain)
					atomic.StoreUint32(&m.debugChainRead, 0)
				}
			}
			m.counter.Hit++
			return node, hashListNext
		}
		hashListNext = node.hashListNext
	}
	m.counter.Miss++
	m.counter.totalScan += width
	if isAdd {
		width++
	}
	if width > m.counter.Max {
		m.counter.Max = width
	}

	if atomic.LoadUint32(&m.debugChainRead) == 1 {
		// 已读，构造新的chain
		if threshold := int(atomic.LoadUint32(&m.collisionChainDebugThreshold)); threshold > 0 && width >= threshold {
			chain := make([]byte, m.KeySize()*width)
			offset := 0
			if isAdd {
				binary.BigEndian.PutUint64(chain, key)
				offset += m.KeySize()
			}
			m.generateCollisionChainInLongKey(chain[offset:], slot)
			m.debugChain.Store(chain)
			atomic.StoreUint32(&m.debugChainRead, 0)
		}
	}
	return nil, -1
}

func (m *U64DoubleKeyLRU) generateCollisionChainInLongKey(bs []byte, index int32) {
	offset := 0
	bsLen := len(bs)

	for hashListNext := m.hashSlotHead[index]; hashListNext != -1 && offset < bsLen; {
		node := m.getNode(hashListNext)
		binary.BigEndian.PutUint64(bs[offset:], node.key)
		offset += m.KeySize()
		hashListNext = node.hashListNext
	}
}

func (m *U64DoubleKeyLRU) generateCollisionChainInShortKey(bs []byte, index int32) {
	offset := 0
	bsLen := len(bs)

	for relationHashListNext := m.relationHashSlotHead[index]; relationHashListNext != -1 && offset < bsLen; {
		node := m.getNode(relationHashListNext)
		binary.BigEndian.PutUint64(bs[offset:], node.shortKey)
		offset += m.KeySize()
		relationHashListNext = node.relationHashListNext
	}
}

func (m *U64DoubleKeyLRU) GetCollisionChain() []byte {
	if atomic.LoadUint32(&m.debugChainRead) == 1 {
		return nil
	}
	chain := m.debugChain.Load()
	atomic.StoreUint32(&m.debugChainRead, 1)
	if chain == nil {
		return nil
	}
	return chain.([]byte)
}

func (m *U64DoubleKeyLRU) SetCollisionChainDebugThreshold(t int) {
	atomic.StoreUint32(&m.collisionChainDebugThreshold, uint32(t))
	// 标记为已读，刷新链
	if t > 0 {
		atomic.StoreUint32(&m.debugChainRead, 1)
	}
}

func (m *U64DoubleKeyLRU) Get(key uint64, peek bool) (interface{}, bool) {
	node, hashIndex := m.find(key, false)
	if node != nil {
		if !peek {
			m.updateNode(node, hashIndex, node.value)
		}
		return node.value, true
	}
	return nil, false
}

func (m *U64DoubleKeyLRU) PeekByShortKey(key uint64) ([]interface{}, bool) {
	maxScan := 0
	values := []interface{}{}
	slot := m.compressRelationHash(key)

	for relationHashListNext := m.relationHashSlotHead[slot]; relationHashListNext != -1; {
		node := m.getNode(relationHashListNext)
		maxScan++
		if node.shortKey == key {
			values = append(values, node.value)
		}
		relationHashListNext = node.relationHashListNext
	}
	if maxScan > m.counter.MaxShortBucket {
		m.counter.MaxShortBucket = maxScan
	}

	if threshold := int(atomic.LoadUint32(&m.collisionChainDebugThreshold)); threshold > 0 && maxScan >= threshold {
		chain := make([]byte, m.KeySize()*maxScan)
		m.generateCollisionChainInShortKey(chain, slot)
		m.debugChain.Store(chain)
		atomic.StoreUint32(&m.debugChainRead, 0)
	}

	if len(values) > 0 {
		return values, true
	}
	return nil, false
}

func (m *U64DoubleKeyLRU) Walk(callback func(key uint64, value interface{})) {
	for i := m.timeListHead; i != -1; {
		node := m.getNode(i)
		callback(node.key, node.value)
		i = node.timeListNext
	}
}

func (m *U64DoubleKeyLRU) Clear() {
	for i := range m.ringBuffer {
		if m.ringBuffer[i] != nil {
			for j := 0; j < len(m.ringBuffer[i]); j++ {
				m.ringBuffer[i][j].value = nil
			}
			u64DoubleKeyLRUNodeBlockPool.Put(m.ringBuffer[i])
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

	atomic.StoreUint32(&m.debugChainRead, 1)
}

func (m *U64DoubleKeyLRU) compressHash(hash uint64) int32 {
	return keyhash.Jenkins(hash) & (m.hashSlots - 1)
}

func (m *U64DoubleKeyLRU) compressRelationHash(hash uint64) int32 {
	return keyhash.Jenkins(hash) & (m.relationHashSlots - 1)
}

func NewU64DoubleKeyLRU(module string, hashSlots, relationHashSlots, capacity int, opts ...stats.OptionStatTags) *U64DoubleKeyLRU {
	hashSlots, hashSlotBits := minPowerOfTwo(hashSlots)
	relationHashSlots, relationHashSlotBits := minPowerOfTwo(relationHashSlots)

	m := &U64DoubleKeyLRU{
		ringBuffer:   make([]u64DoubleKeyLRUNodeBlock, (capacity+_BLOCK_SIZE)/_BLOCK_SIZE+1),
		hashSlots:    int32(hashSlots),
		hashSlotBits: uint32(hashSlotBits),
		hashSlotHead: make([]int32, hashSlots),

		relationHashSlots:    int32(relationHashSlots),
		relationHashSlotBits: uint32(relationHashSlotBits),
		relationHashSlotHead: make([]int32, relationHashSlots),

		timeListHead: -1,
		timeListTail: -1,
		capacity:     capacity,
		counter:      &DoubleKeyLRUCounter{},
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
	hmap.RegisterForDebug(m)

	return m
}
