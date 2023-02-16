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

package utils

import (
	"encoding/binary"
	"sync"
	"sync/atomic"

	"github.com/deepflowio/deepflow/server/libs/hmap"
	"github.com/deepflowio/deepflow/server/libs/hmap/keyhash"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	_BLOCK_SIZE_BITS = 8
	_BLOCK_SIZE      = 1 << _BLOCK_SIZE_BITS
	_BLOCK_SIZE_MASK = _BLOCK_SIZE - 1
)

type Counter struct {
	Max                  int `statsd:"max-bucket"`
	Size                 int `statsd:"size"`
	AvgScan              int `statsd:"avg-scan"` // 平均扫描次数
	totalScan, scanTimes int
}

type u128IDMapNode struct {
	key0  uint64
	key1  uint64
	value interface{}

	next int32 // 表示节点所在冲突链的下一个节点的 buffer 数组下标
	slot int32 // 记录 node 对应的哈希 slot ，为了避免 Clear 函数遍历整个 slotHead 数组
}

type KeyValue struct {
	key0  uint64
	key1  uint64
	value interface{}
}

func (k KeyValue) GetData() (uint64, uint64, interface{}) {

	return k.key0, k.key1, k.value
}

func (n *u128IDMapNode) equal(key0, key1 uint64) bool {
	return n.key0 == key0 && n.key1 == key1
}

var blankU128MapNodeForInit u128IDMapNode

type u128IDMapNodeBlock []u128IDMapNode

var u128IDMapNodeBlockPool = sync.Pool{New: func() interface{} {
	return u128IDMapNodeBlock(make([]u128IDMapNode, _BLOCK_SIZE))
}}

// 注意：不是线程安全的
type U128IDMap struct {
	utils.Closable

	id string

	buffer []u128IDMapNodeBlock // 存储Map节点，以矩阵的方式组织，提升内存申请释放效率

	slotHead []int32 // 哈希桶，slotHead[i] 表示哈希值为 i 的冲突链的第一个节点为 buffer[[ slotHead[i]] ]]
	size     int     // buffer中存储的有效节点总数
	width    int     // 哈希桶中最大冲突链长度

	hashSlotBits uint32 // 哈希桶数量总是2^N，记录末尾0比特的数量用于compressHash

	counter *Counter

	collisionChainDebugThreshold uint32       // scan宽度超过该值时保留冲突链信息，为0时不保存
	debugChain                   atomic.Value // 冲突链，类型为[]byte
	debugChainRead               uint32       // 冲突链是否已读，如果已读替换为新的 (atomic.Value无法清空)
}

func NewU128IDMap(module string, hashSlots uint32, opts ...stats.OptionStatTags) *U128IDMap {
	m := NewU128IDMapNoStats(module, hashSlots)

	statOptions := []stats.Option{stats.OptionStatTags{"module": module}}
	for _, opt := range opts {
		statOptions = append(statOptions, opt)
	}
	stats.RegisterCountable("idmap", m, statOptions...)
	hmap.RegisterForDebug(m)
	return m
}

func NewU128IDMapNoStats(module string, hashSlots uint32) *U128IDMap {
	if hashSlots >= 1<<30 {
		panic("hashSlots is too large")
	}

	i := uint32(1)
	for ; 1<<i < hashSlots; i++ {
	}
	hashSlots = 1 << i

	m := &U128IDMap{
		buffer:       make([]u128IDMapNodeBlock, 0),
		slotHead:     make([]int32, hashSlots),
		hashSlotBits: i,
		counter:      &Counter{},
		id:           "idmap128-" + module,
	}

	for i := uint32(0); i < hashSlots; i++ {
		m.slotHead[i] = -1
	}

	return m
}

func (m *U128IDMap) ID() string {
	return m.id
}

func (m *U128IDMap) KeySize() int {
	return 128 / 8
}

func (m *U128IDMap) Close() error {
	hmap.DeregisterForDebug(m)
	return m.Closable.Close()
}

func (m *U128IDMap) NoStats() *U128IDMap {
	m.Close()
	return m
}

func (m *U128IDMap) Size() int {
	return m.size
}

func (m *U128IDMap) Width() int {
	return m.width
}

func (m *U128IDMap) compressHash(key0, key1 uint64) int32 {
	return keyhash.Jenkins128(key0, key1) & int32(len(m.slotHead)-1)
}

func (m *U128IDMap) find(key0, key1 uint64, isAdd bool) *u128IDMapNode {
	slot := m.compressHash(key0, key1)
	head := m.slotHead[slot]

	m.counter.scanTimes++
	width := 0
	next := head
	for next != -1 {
		width++
		node := &m.buffer[next>>_BLOCK_SIZE_BITS][next&_BLOCK_SIZE_MASK]
		if node.equal(key0, key1) {
			m.counter.totalScan += width
			if m.counter.Max < width {
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
			return node
		}
		next = node.next
	}
	m.counter.totalScan += width
	if isAdd {
		width++
	}
	if m.width < width {
		m.width = width
	}
	if m.counter.Max < width {
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
	return nil
}

func (m *U128IDMap) generateCollisionChainIn(bs []byte, index int32) {
	nodeID := m.slotHead[index]
	offset := 0
	bsLen := len(bs)

	for nodeID != -1 && offset < bsLen {
		node := &m.buffer[nodeID>>_BLOCK_SIZE_BITS][nodeID&_BLOCK_SIZE_MASK]
		binary.BigEndian.PutUint64(bs[offset:], node.key0)
		binary.BigEndian.PutUint64(bs[offset+8:], node.key1)
		offset += m.KeySize()
		nodeID = node.next
	}
}

func (m *U128IDMap) GetCollisionChain() []byte {
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

func (m *U128IDMap) SetCollisionChainDebugThreshold(t int) {
	atomic.StoreUint32(&m.collisionChainDebugThreshold, uint32(t))
	// 标记为已读，刷新链
	if t > 0 {
		atomic.StoreUint32(&m.debugChainRead, 1)
	}
}

// 第一个返回值表示value，第二个返回值表示是否进行了Add。若key已存在，指定overwrite=true可覆写value。
func (m *U128IDMap) AddOrGet(key0, key1 uint64, value interface{}, overwrite bool) (interface{}, bool) {
	node := m.find(key0, key1, true)
	if node != nil {
		if overwrite {
			node.value = value
		}
		return node.value, false
	}

	slot := m.compressHash(key0, key1)
	head := m.slotHead[slot]

	if m.size >= len(m.buffer)<<_BLOCK_SIZE_BITS { // expand
		m.buffer = append(m.buffer, u128IDMapNodeBlockPool.Get().(u128IDMapNodeBlock))
	}
	node = &m.buffer[m.size>>_BLOCK_SIZE_BITS][m.size&_BLOCK_SIZE_MASK]
	node.key0 = key0
	node.key1 = key1
	node.value = value
	node.next = head
	node.slot = int32(slot)

	m.slotHead[slot] = int32(m.size)
	m.size++

	if m.counter.Size < m.size {
		m.counter.Size = m.size
	}

	return value, true
}

func (m *U128IDMap) AddOrGetWithSlice(key []byte, _ uint32, value interface{}, overwrite bool) (interface{}, bool) {
	if len(key) != 16 {
		panic("传入key的长度不等于 16 字节")
	}
	return m.AddOrGet(binary.BigEndian.Uint64(key), binary.BigEndian.Uint64(key[8:]), value, overwrite)
}

func (m *U128IDMap) Get(key0, key1 uint64) (interface{}, bool) {
	if node := m.find(key0, key1, false); node != nil {
		return node.value, true
	}
	return nil, false
}

func (m *U128IDMap) GetWithSlice(key []byte, _ uint32) (interface{}, bool) {
	if len(key) != 16 {
		panic("传入key的长度不等于 16 字节")
	}
	return m.Get(binary.BigEndian.Uint64(key), binary.BigEndian.Uint64(key[8:]))
}

func (m *U128IDMap) GetCounter() interface{} {
	var counter *Counter
	counter, m.counter = m.counter, &Counter{Size: m.size}
	if counter.scanTimes != 0 {
		counter.AvgScan = counter.totalScan / counter.scanTimes
	}
	return counter
}

func (m *U128IDMap) Clear() {
	for i := 0; i < m.size; i += _BLOCK_SIZE {
		for j := 0; j < _BLOCK_SIZE && i+j < m.size; j++ {
			node := &m.buffer[i>>_BLOCK_SIZE_BITS][j]
			m.slotHead[node.slot] = -1
			*node = blankU128MapNodeForInit
		}
		u128IDMapNodeBlockPool.Put(m.buffer[i>>_BLOCK_SIZE_BITS])
		m.buffer[i>>_BLOCK_SIZE_BITS] = nil
	}

	m.buffer = m.buffer[:0]

	m.size = 0
	m.width = 0

	atomic.StoreUint32(&m.debugChainRead, 1)
}

func (m *U128IDMap) Iter() <-chan KeyValue {
	ch := make(chan KeyValue)
	go func() {
		for i := 0; i < m.size; i += _BLOCK_SIZE {
			for j := 0; j < _BLOCK_SIZE && i+j < m.size; j++ {
				node := m.buffer[i>>_BLOCK_SIZE_BITS][j]
				ch <- KeyValue{
					key0:  node.key0,
					key1:  node.key1,
					value: node.value,
				}
			}
		}
		close(ch)
	}()
	return ch
}

//var _ UBigIDMap = &U128IDMap{}
