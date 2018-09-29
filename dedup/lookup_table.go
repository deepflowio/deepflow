package dedup

import (
	"bytes"
	"time"
)

const (
	ENTRY_TIMEOUT = 100 * time.Millisecond

	// 哈希表大小限制
	HASH_TABLE_SIZE_BIT_OFFSET = 17                              // 必须大于等于15
	HASH_TABLE_SIZE            = 1 << HASH_TABLE_SIZE_BIT_OFFSET // 128K

	ELEMENTS_LIMIT = HASH_TABLE_SIZE * 4

	PACKET_ID_SIZE = 64
)

type DedupTable struct {
	hashTable    *HashTable
	queue        *List
	buffer       *List
	overwriteTTL bool
	counter      *Counter
}

type Counter struct {
	Total      uint64 `statsd:"total,counter"`
	Hit        uint64 `statsd:"hit,counter"`
	Timeout    uint64 `statsd:"timeout,counter"`
	MaxBucket  int    `statsd:"max_bucket,gauge"`
	LoadFactor uint   `statsd:"load_factor,gauge"`
}

func (t *DedupTable) GetCounter() interface{} {
	counter := &Counter{}
	t.counter, counter = counter, t.counter
	return counter
}

type PacketId [PACKET_ID_SIZE]byte

func compressHash(hash uint32) uint32 {
	mask := uint32(HASH_TABLE_SIZE - 1)
	return hash&mask ^ hash>>(32-HASH_TABLE_SIZE_BIT_OFFSET)
}

type LinkedPacketDesc struct {
	timestamp time.Duration
	hash      uint32   // 哈希key
	id        uint64   // IP ID + frag + total_length + chksum
	packetId  PacketId // 报文标识字段，用于精确标识报文，目前粗糙地取报文头部一段长度
}

type List struct {
	head *ListNode
	tail *ListNode
	size int
}

type ListNode struct {
	desc *LinkedPacketDesc
	prev *ListNode
	next *ListNode
	peer *ListNode
}

func (list *List) pushBack(node *ListNode) {
	if node == nil {
		return
	}

	if list.head == nil {
		list.head = node
		list.tail = node
	} else {
		list.tail.next = node
		node.prev = list.tail
		list.tail = node
	}
	list.size++
}

func (list *List) popFront() *ListNode {
	node := list.head
	if node == nil {
		return node
	}

	if list.head == list.tail {
		list.head = nil
		list.tail = nil
	} else {
		list.head = list.head.next
		list.head.prev = nil
	}
	list.size--

	node.prev = nil
	node.next = nil
	return node
}

func (list *List) remove(node *ListNode) {
	if node == nil {
		return
	}

	if list.head == list.tail {
		list.head = nil
		list.tail = nil
	} else {
		if node.prev != nil {
			node.prev.next = node.next
		} else {
			list.head = node.next
			list.head.prev = nil
		}
		if node.next != nil {
			node.next.prev = node.prev
		} else {
			list.tail = node.prev
			list.tail.next = nil
		}
	}
	list.size--

	node.prev = nil
	node.next = nil
}

func (t *DedupTable) SetOverwriteTTL(b bool) {
	t.overwriteTTL = b
}

func (t *DedupTable) allocateNodePair(timestamp time.Duration, hash uint32, id uint64, packetId PacketId) (qnode, bnode *ListNode) {
	if t.buffer.head == nil {
		qnode = &ListNode{}
		qnode.desc = &LinkedPacketDesc{
			timestamp: timestamp,
			hash:      hash,
			id:        id,
		}
		copy(qnode.desc.packetId[:], packetId[:])

		bnode = &ListNode{}
		bnode.desc = qnode.desc

		qnode.peer = bnode
		bnode.peer = qnode
		return qnode, bnode
	}

	qnode = t.buffer.popFront()
	qnode.desc.timestamp = timestamp
	qnode.desc.hash = hash
	qnode.desc.id = id
	copy(qnode.desc.packetId[:], packetId[:])

	bnode = t.buffer.popFront()

	return qnode, bnode
}

func (t *DedupTable) releaseToBuffer(qnode, bnode *ListNode) {
	t.buffer.pushBack(qnode)
	t.buffer.pushBack(bnode)
}

// 因为我们需要比较packetId来确认是否匹配，因此没有办法用库所提供的map或lru
type HashTable [HASH_TABLE_SIZE]*List

func (t *DedupTable) withdraw(hash uint32, id uint64, packetId PacketId) bool {
	bucket := t.hashTable[compressHash(hash)]
	for bnode := bucket.head; bnode != nil; bnode = bnode.next {
		if bnode.desc.hash == hash && bnode.desc.id == id && bytes.Equal(bnode.desc.packetId[:], packetId[:]) {
			qnode := bnode.peer
			t.queue.remove(qnode)
			bucket.remove(bnode)
			t.releaseToBuffer(qnode, bnode)
			return true
		}
	}
	return false
}

func (t *DedupTable) enQueue(qnode, bnode *ListNode) {
	if t.queue.size >= ELEMENTS_LIMIT {
		t.deQueue() // 无需记录此Counter，目前Hash空间不可能丢
	}
	key := compressHash(qnode.desc.hash)

	t.queue.pushBack(qnode)
	t.hashTable[key].pushBack(bnode)

	if t.hashTable[key].size > t.counter.MaxBucket {
		t.counter.MaxBucket = t.hashTable[key].size
	}
}

func (t *DedupTable) deQueue() {
	qnode := t.queue.popFront()
	if qnode != nil {
		bnode := t.hashTable[compressHash(qnode.desc.hash)].popFront() // queue和bucket的第一个一定相同
		t.releaseToBuffer(qnode, bnode)
	}
	return
}

func (t *DedupTable) deleteTimeout(timestamp time.Duration) {
	for t.queue.head != nil && timestamp-t.queue.head.desc.timestamp > ENTRY_TIMEOUT {
		t.counter.Timeout++
		t.deQueue()
	}
}

func (t *DedupTable) lookup(hash uint32, id uint64, timestamp time.Duration, packetId PacketId) bool {
	t.deleteTimeout(timestamp)
	t.counter.Total++

	if t.withdraw(hash, id, packetId) {
		t.counter.Hit++
		return true
	}

	qnode, bnode := t.allocateNodePair(timestamp, hash, id, packetId)
	t.enQueue(qnode, bnode)
	return false
}
