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

package dedup

import (
	"bytes"
	"sync"
	"time"

	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	ENTRY_TIMEOUT = 100 * time.Millisecond

	// 哈希表大小限制
	HASH_TABLE_SIZE_BIT_OFFSET = 17                              // 必须大于等于15
	HASH_TABLE_SIZE            = 1 << HASH_TABLE_SIZE_BIT_OFFSET // 128K

	ELEMENTS_LIMIT = HASH_TABLE_SIZE * 4

	PACKET_ID_SIZE_V6 = 96
	PACKET_ID_SIZE_V4 = 64
)

const (
	_BLOCK_SIZE_BITS = 8
	_BLOCK_SIZE      = 1 << _BLOCK_SIZE_BITS
	_BLOCK_SIZE_MASK = _BLOCK_SIZE - 1
)

type packetDedupMapNode struct {
	keySize   int32         // IPv6时为96，其它情况下为64
	hash      uint32        // 哈希key
	id        uint64        // IP ID + frag + total length + chksum (IPv4), Flow label + payload length + next header (IPv6)
	timestamp time.Duration // Packet timestamp，当两个包相同且在 ENTRY_TIMEOUT 之内收到时认为是 dup 的

	next int32 // 表示节点所在冲突链的下一个节点的 buffer 数组下标
	slot int32 // 记录 node 对应的哈希 slot ，置为 -1 表示 node 已标记为删除，占用的空间将会随 deleteTimeout 释放

	key [PACKET_ID_SIZE_V6]byte // 原始包头
}

func (n *packetDedupMapNode) equal(v *packetDedupMapNode) bool {
	return n.hash == v.hash && n.id == v.id && bytes.Compare(n.key[:n.keySize], v.key[:v.keySize]) == 0
}

var blankPacketDedupMapNodeForInit packetDedupMapNode

type packetDedupMapNodeBlock []packetDedupMapNode

var packetDedupMapNodeBlockPool = sync.Pool{New: func() interface{} {
	return packetDedupMapNodeBlock(make([]packetDedupMapNode, _BLOCK_SIZE))
}}

// 注意：不是线程安全的，且要求Packet的时间戳是非降序列
type PacketDedupMap struct {
	utils.Closable
	counter *PacketDedupMapCounter

	ignoreTTL        bool                      // 比较包头内容时，是否忽略TTL的差异
	ringBuffer       []packetDedupMapNodeBlock // 存储Map节点，以矩阵环的方式组织，提升内存申请释放效率
	bufferStartIndex int32                     // ringBuffer中的开始下标（矩阵下标），闭区间
	bufferEndIndex   int32                     // ringBuffer中的结束下标（矩阵下标），开区间

	slotHead []int32 // 哈希桶，slotHead[i] 表示哈希值为 i 的冲突链的第一个节点为 buffer[[ slotHead[i] ]]
	size     int     // buffer中占用的节点总数，包括由于哈希命中提前删除的节点
	width    int     // 哈希桶中最大冲突链长度

	lookupNode packetDedupMapNode // 用于查询的Node，避免重复申请内存
}

type PacketDedupMapCounter struct {
	Total     uint64 `statsd:"total,counter"`
	Hit       uint64 `statsd:"hit,counter"`
	Timeout   uint64 `statsd:"timeout,counter"`
	Drop      uint64 `statsd:"drop,counter"`
	MaxBucket int    `statsd:"max_bucket,gauge"`
}

func (m *PacketDedupMap) GetCounter() interface{} {
	counter := &PacketDedupMapCounter{}
	m.counter, counter = counter, m.counter

	counter.MaxBucket = m.width
	m.width = 0

	return counter
}

func compressHash(hash uint32) uint32 {
	return hash&uint32(HASH_TABLE_SIZE-1) ^ hash>>(32-HASH_TABLE_SIZE_BIT_OFFSET)
}

func (m *PacketDedupMap) Size() int {
	return m.size
}

func (m *PacketDedupMap) Width() int {
	return m.width
}

func (t *PacketDedupMap) SetIgnoreTTL(b bool) {
	t.ignoreTTL = b
}

// 若存在则delete并返回true，否则add并返回false
func (m *PacketDedupMap) deleteOrAdd() bool {
	slot := compressHash(m.lookupNode.hash)
	head := m.slotHead[slot]

	width := 0
	prev := int32(-1)
	next := head
	for next != -1 {
		width++
		node := &m.ringBuffer[next>>_BLOCK_SIZE_BITS][next&_BLOCK_SIZE_MASK]
		if node.equal(&m.lookupNode) {
			m.counter.Hit++
			if prev != -1 {
				prevNode := &m.ringBuffer[prev>>_BLOCK_SIZE_BITS][prev&_BLOCK_SIZE_MASK]
				prevNode.next = node.next
			} else {
				m.slotHead[slot] = node.next
			}
			*node = blankPacketDedupMapNodeForInit
			node.slot = -1 // 哈希命中，提前标记节点已删除，但无需更新m.size
			return true
		}
		prev = next
		next = node.next
	}

	// 未命中，添加节点
	row := m.bufferEndIndex >> _BLOCK_SIZE_BITS
	col := m.bufferEndIndex & _BLOCK_SIZE_MASK
	if m.ringBuffer[row] == nil {
		m.ringBuffer[row] = packetDedupMapNodeBlockPool.Get().(packetDedupMapNodeBlock)
	}
	node := &m.ringBuffer[row][col]
	*node = m.lookupNode
	node.next = -1
	node.slot = int32(slot)
	if prev != -1 {
		prevNode := &m.ringBuffer[prev>>_BLOCK_SIZE_BITS][prev&_BLOCK_SIZE_MASK]
		prevNode.next = m.bufferEndIndex
	} else {
		m.slotHead[slot] = int32(m.bufferEndIndex)
	}

	m.bufferEndIndex++
	if m.bufferEndIndex>>_BLOCK_SIZE_BITS >= int32(len(m.ringBuffer)) {
		m.bufferEndIndex = 0
	}
	m.size++
	if m.width < width+1 {
		m.width = width + 1
	}

	return false
}

func (m *PacketDedupMap) deleteTimeout(timestamp time.Duration) {
	i := m.bufferStartIndex
	for i != m.bufferEndIndex {
		row := i >> _BLOCK_SIZE_BITS
		col := i & _BLOCK_SIZE_MASK
		node := &m.ringBuffer[row][col]

		if node.slot != -1 {
			if m.size <= ELEMENTS_LIMIT {
				if timestamp-node.timestamp <= ENTRY_TIMEOUT {
					break
				}
				m.counter.Timeout++
			} else {
				m.counter.Drop++ // 容量超出，继续删除
			}

			m.slotHead[node.slot] = node.next // node一定是哈希桶的第一个
			*node = blankPacketDedupMapNodeForInit
			node.slot = -1
		}

		m.size--
		if col == _BLOCK_SIZE_MASK {
			packetDedupMapNodeBlockPool.Put(m.ringBuffer[row])
			m.ringBuffer[row] = nil
		}

		i++
		if i>>_BLOCK_SIZE_BITS == int32(len(m.ringBuffer)) {
			i = 0
		}
	}
	m.bufferStartIndex = i
}

// 若存在则返回true，否则返回false
func (m *PacketDedupMap) lookup() bool {
	m.deleteTimeout(m.lookupNode.timestamp)

	m.counter.Total++
	return m.deleteOrAdd()
}
