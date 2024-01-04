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
	"encoding/binary"
	"sync"
	"sync/atomic"

	"github.com/deepflowio/deepflow/server/libs/hmap"
	"github.com/deepflowio/deepflow/server/libs/hmap/keyhash"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
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

	id string

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

	counter *Counter

	collisionChainDebugThreshold uint32       // scan宽度超过该值时保留冲突链信息，为0时不保存
	debugChain                   atomic.Value // 冲突链，类型为[]byte
	debugChainRead               uint32       // 冲突链是否已读，如果已读替换为新的 (atomic.Value无法清空)
}

func (m *U64LRU) ID() string {
	return m.id
}

func (m *U64LRU) KeySize() int {
	return 64 / 8
}

func (m *U64LRU) Close() error {
	hmap.DeregisterForDebug(m)
	return m.Closable.Close()
}

func (m *U64LRU) NoStats() *U64LRU {
	m.Close()
	return m
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
	var counter *Counter
	counter, m.counter = m.counter, &Counter{}
	if counter.scanTimes != 0 {
		counter.AvgScan = counter.totalScan / counter.scanTimes
	}
	counter.Size = m.size
	return counter
}

func (m *U64LRU) Add(key uint64, value interface{}) {
	node, hashIndex := m.find(key, true)
	if node != nil {
		m.updateNode(node, hashIndex, value)
		return
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

func (m *U64LRU) find(key uint64, isAdd bool) (*u64LRUNode, int32) {
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
					m.generateCollisionChainIn(chain, slot)
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
			m.generateCollisionChainIn(chain[offset:], slot)
			m.debugChain.Store(chain)
			atomic.StoreUint32(&m.debugChainRead, 0)
		}
	}
	return nil, -1
}

func (m *U64LRU) generateCollisionChainIn(bs []byte, index int32) {
	offset := 0
	bsLen := len(bs)

	for hashListNext := m.hashSlotHead[index]; hashListNext != -1 && offset < bsLen; {
		node := m.getNode(hashListNext)
		binary.BigEndian.PutUint64(bs[offset:], node.key)
		offset += m.KeySize()
		hashListNext = node.hashListNext
	}
}

func (m *U64LRU) GetCollisionChain() []byte {
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

func (m *U64LRU) SetCollisionChainDebugThreshold(t int) {
	atomic.StoreUint32(&m.collisionChainDebugThreshold, uint32(t))
	// 标记为已读，刷新链
	if t > 0 {
		atomic.StoreUint32(&m.debugChainRead, 1)
	}
}

func (m *U64LRU) Get(key uint64, peek bool) (interface{}, bool) {
	node, hashIndex := m.find(key, false)
	if node != nil {
		if !peek {
			m.updateNode(node, hashIndex, node.value)
		}
		return node.value, true
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

	atomic.StoreUint32(&m.debugChainRead, 1)
}

func (m *U64LRU) compressHash(hash uint64) int32 {
	return keyhash.Jenkins(hash) & (m.hashSlots - 1)
}

func NewU64LRU(module string, hashSlots, capacity int, opts ...stats.OptionStatTags) *U64LRU {
	m := NewU64LRUNoStats(module, hashSlots, capacity)

	statOptions := []stats.Option{stats.OptionStatTags{"module": module}}
	for _, opt := range opts {
		statOptions = append(statOptions, opt)
	}
	stats.RegisterCountable("lru", m, statOptions...)

	hmap.RegisterForDebug(m)

	return m
}

func NewU64LRUNoStats(module string, hashSlots, capacity int) *U64LRU {
	hashSlots, hashSlotBits := minPowerOfTwo(hashSlots)

	m := &U64LRU{
		ringBuffer:   make([]u64LRUNodeBlock, (capacity+_BLOCK_SIZE)/_BLOCK_SIZE+1),
		hashSlots:    int32(hashSlots),
		hashSlotBits: uint32(hashSlotBits),
		hashSlotHead: make([]int32, hashSlots),
		timeListHead: -1,
		timeListTail: -1,
		capacity:     capacity,
		counter:      &Counter{},
		id:           "lru64-" + module,
	}

	for i := 0; i < len(m.hashSlotHead); i++ {
		m.hashSlotHead[i] = -1
	}

	return m
}
