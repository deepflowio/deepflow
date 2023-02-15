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

type u128LRUNode struct {
	key0  uint64
	key1  uint64
	value interface{}

	hashListNext *u128LRUNode // 表示节点所在冲突链的下一个节点的 buffer 数组下标，-1 表示不存在
	hashListPrev *u128LRUNode // 表示节点所在冲突链的上一个节点的 buffer 数组下标，-1 表示不存在
	timeListNext *u128LRUNode // 时间链表，含义与冲突链类似
	timeListPrev *u128LRUNode // 时间链表，含义与冲突链类似

	hash  int32
	index int32
}

var blankU128LRUNodeForInit u128LRUNode

type u128LRUNodeBlock []u128LRUNode

var u128LRUNodeBlockPool = sync.Pool{New: func() interface{} {
	return u128LRUNodeBlock(make([]u128LRUNode, _BLOCK_SIZE))
}}

// 注意：不是线程安全的
type U128LRU struct {
	utils.Closable

	id string

	ringBuffer       []u128LRUNodeBlock // 存储Map节点，以矩阵环的方式组织，提升内存申请释放效率
	bufferStartIndex int32              // ringBuffer中的开始下标（二维矩阵下标），闭区间
	bufferEndIndex   int32              // ringBuffer中的结束下标（二维矩阵下标），开区间

	hashSlots    int32  // 上取整至2^N，哈希桶个数
	hashSlotBits uint32 // hashSlots中低位连续0比特个数

	hashSlotHead []*u128LRUNode // 哈希桶，hashSlotHead[i] 表示哈希值为 i 的冲突链的第一个节点为 buffer[[ hashSlotHead[i] ]]
	timeListHead *u128LRUNode
	timeListTail *u128LRUNode

	capacity int // 最大容纳的Flow个数
	size     int // 当前容纳的Flow个数

	counter *Counter

	collisionChainDebugThreshold uint32       // scan宽度超过该值时保留冲突链信息，为0时不保存
	debugChain                   atomic.Value // 冲突链，类型为[]byte
	debugChainRead               uint32       // 冲突链是否已读，如果已读替换为新的 (atomic.Value无法清空)
}

func (m *U128LRU) ID() string {
	return m.id
}

func (m *U128LRU) KeySize() int {
	return 128 / 8
}

func (m *U128LRU) Close() error {
	hmap.DeregisterForDebug(m)
	return m.Closable.Close()
}

func (m *U128LRU) NoStats() *U128LRU {
	m.Close()
	return m
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

func (m *U128LRU) pushNodeToHashList(node *u128LRUNode, hash int32) {
	node.hashListNext = m.hashSlotHead[hash]
	node.hashListPrev = nil
	if node.hashListNext != nil {
		node.hashListNext.hashListPrev = node
	}
	m.hashSlotHead[hash] = node
}

func (m *U128LRU) pushNodeToTimeList(node *u128LRUNode, nodeIndex int32) {
	node.timeListNext = m.timeListHead
	node.timeListPrev = nil
	if node.timeListNext != nil {
		node.timeListNext.timeListPrev = node
	}
	m.timeListHead = node
	if m.timeListTail == nil {
		m.timeListTail = node
	}
}

func (m *U128LRU) removeNodeFromHashList(node, newNext, newPrev *u128LRUNode) {
	if node.hashListPrev != nil {
		node.hashListPrev.hashListNext = newNext
	} else {
		m.hashSlotHead[node.hash] = newNext
	}

	if node.hashListNext != nil {
		node.hashListNext.hashListPrev = newPrev
	}
}

func (m *U128LRU) removeNodeFromTimeList(node, newNext, newPrev *u128LRUNode) {
	prevNode := node.timeListPrev
	if prevNode != nil {
		prevNode.timeListNext = newNext
	} else {
		m.timeListHead = newNext
	}

	nextNode := node.timeListNext
	if nextNode != nil {
		nextNode.timeListPrev = newPrev
	} else {
		m.timeListTail = newPrev
	}
}

func (m *U128LRU) removeNode(node *u128LRUNode) {
	// 从哈希链表、时间链表中删除
	m.removeNodeFromHashList(node, node.hashListNext, node.hashListPrev)
	m.removeNodeFromTimeList(node, node.timeListNext, node.timeListPrev)

	// 将节点交换至buffer头部
	if node.index != m.bufferStartIndex {
		firstNode := m.getNode(m.bufferStartIndex)
		// 将firstNode内容拷贝至node
		*node = *firstNode
		// 修改firstNode在哈希链、时间链的上下游指向node
		m.removeNodeFromHashList(firstNode, node, node)
		m.removeNodeFromTimeList(firstNode, node, node)
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

func (m *U128LRU) updateNode(node *u128LRUNode, value interface{}) {
	if node != m.timeListHead {
		// 从时间链表中删除
		m.removeNodeFromTimeList(node, node.timeListNext, node.timeListPrev)
		// 插入时间链表头部
		m.pushNodeToTimeList(node, node.index)
	}
	if node != m.hashSlotHead[node.hash] {
		// 从hash链表中删除
		m.removeNodeFromHashList(node, node.hashListNext, node.hashListPrev)
		// 插入到hash链表头部
		m.pushNodeToHashList(node, node.hash)
	}

	node.value = value
}

func (m *U128LRU) newNode(key0, key1 uint64, value interface{}, hash int32) {
	// buffer空间检查
	if m.size >= m.capacity {
		m.removeNode(m.timeListTail)
	}
	row := m.bufferEndIndex >> _BLOCK_SIZE_BITS
	col := m.bufferEndIndex & _BLOCK_SIZE_MASK
	if m.ringBuffer[row] == nil {
		m.ringBuffer[row] = u128LRUNodeBlockPool.Get().(u128LRUNodeBlock)
	}
	node := &m.ringBuffer[row][col]
	m.size++

	// 新节点加入哈希链
	m.pushNodeToHashList(node, hash)
	// 新节点加入时间链
	m.pushNodeToTimeList(node, m.bufferEndIndex)
	// 更新key、value
	node.key0 = key0
	node.key1 = key1
	node.value = value
	node.hash = hash
	node.index = m.bufferEndIndex

	// 更新buffer信息
	m.bufferEndIndex = m.incIndex(m.bufferEndIndex)
}

func (m *U128LRU) GetCounter() interface{} {
	var counter *Counter
	counter, m.counter = m.counter, &Counter{}
	if counter.scanTimes != 0 {
		counter.AvgScan = counter.totalScan / counter.scanTimes
	}
	counter.Size = m.size
	return counter
}

func (m *U128LRU) Add(key0, key1 uint64, value interface{}) {
	node, slot := m.find(key0, key1, true)
	if node != nil {
		m.updateNode(node, value)
		return
	}
	m.newNode(key0, key1, value, slot)
}

func (m *U128LRU) Remove(key0, key1 uint64) {
	for node := m.hashSlotHead[m.compressHash(key0, key1)]; node != nil; node = node.hashListNext {
		if node.key0 == key0 && node.key1 == key1 {
			m.removeNode(node)
			return
		}
	}
}

func (m *U128LRU) find(key0, key1 uint64, isAdd bool) (*u128LRUNode, int32) {
	m.counter.scanTimes++
	width := 0
	slot := m.compressHash(key0, key1)
	for node := m.hashSlotHead[slot]; node != nil; node = node.hashListNext {
		width++
		if node.key0 == key0 && node.key1 == key1 {
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
			return node, slot
		}
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
				binary.BigEndian.PutUint64(chain, key0)
				binary.BigEndian.PutUint64(chain[8:], key1)
				offset += m.KeySize()
			}
			m.generateCollisionChainIn(chain[offset:], slot)
			m.debugChain.Store(chain)
			atomic.StoreUint32(&m.debugChainRead, 0)
		}
	}
	return nil, slot
}

func (m *U128LRU) generateCollisionChainIn(bs []byte, index int32) {
	offset := 0
	bsLen := len(bs)

	for node := m.hashSlotHead[index]; node != nil && offset < bsLen; node = node.hashListNext {
		binary.BigEndian.PutUint64(bs[offset:], node.key0)
		binary.BigEndian.PutUint64(bs[offset+8:], node.key1)
		offset += m.KeySize()
	}
}

func (m *U128LRU) GetCollisionChain() []byte {
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

func (m *U128LRU) SetCollisionChainDebugThreshold(t int) {
	atomic.StoreUint32(&m.collisionChainDebugThreshold, uint32(t))
	// 标记为已读，刷新链
	if t > 0 {
		atomic.StoreUint32(&m.debugChainRead, 1)
	}
}

func (m *U128LRU) Get(key0, key1 uint64, peek bool) (interface{}, bool) {
	node, _ := m.find(key0, key1, false)
	if node != nil {
		if !peek {
			m.updateNode(node, node.value)
		}
		return node.value, true
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
		m.hashSlotHead[i] = nil
	}
	m.timeListHead = nil
	m.timeListTail = nil

	m.size = 0

	atomic.StoreUint32(&m.debugChainRead, 1)
}

func (m *U128LRU) compressHash(key0, key1 uint64) int32 {
	return keyhash.Jenkins128(key0, key1) & (m.hashSlots - 1)
}

type walkCallback func(key0, key1 uint64, value interface{})

func (m *U128LRU) Walk(callback walkCallback) {
	for node := m.timeListHead; node != nil; node = node.timeListNext {
		callback(node.key0, node.key1, node.value)
	}
}

func NewU128LRU(module string, hashSlots, capacity int, opts ...stats.OptionStatTags) *U128LRU {
	m := NewU128LRUNoStats(module, hashSlots, capacity)

	statOptions := []stats.Option{stats.OptionStatTags{"module": module}}
	for _, opt := range opts {
		statOptions = append(statOptions, opt)
	}
	stats.RegisterCountable("lru", m, statOptions...)

	hmap.RegisterForDebug(m)

	return m
}

func NewU128LRUNoStats(module string, hashSlots, capacity int) *U128LRU {
	hashSlots, hashSlotBits := minPowerOfTwo(hashSlots)

	m := &U128LRU{
		ringBuffer:   make([]u128LRUNodeBlock, (capacity+_BLOCK_SIZE)/_BLOCK_SIZE+1),
		hashSlots:    int32(hashSlots),
		hashSlotBits: uint32(hashSlotBits),
		hashSlotHead: make([]*u128LRUNode, hashSlots),
		timeListHead: nil,
		timeListTail: nil,
		capacity:     capacity,
		counter:      &Counter{},
		id:           "lru128-" + module,
	}

	for i := range m.hashSlotHead {
		m.hashSlotHead[i] = nil
	}

	return m
}
