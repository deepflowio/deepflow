package dedup

import (
	"bytes"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

const (
	ENTRY_TIMEOUT = 100 * time.Millisecond

	// 哈希表大小限制
	HASH_TABLE_SIZE_BIT_OFFSET = 17                              // 必须大于等于15
	HASH_TABLE_SIZE            = 1 << HASH_TABLE_SIZE_BIT_OFFSET // 128K

	ELEMENTS_LIMIT = HASH_TABLE_SIZE * 4

	PACKET_ID_SIZE = 64
)

var (
	hashTable *HashTable

	counter = &Counter{}

	queue  *List = &List{}
	buffer *List = &List{}
)

type Counter struct {
	Total      uint64 `statsd:"total"`
	Hit        uint64 `statsd:"hit"`
	Timeout    uint64 `statsd:"timeout"`
	MaxBucket  int    `statsd:"max_bucket"`
	LoadFactor uint   `statsd:"load_factor"`
}

func (c *Counter) GetCounter() interface{} {
	counter, c = &Counter{}, counter
	return c
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

func allocateNodePair(timestamp time.Duration, hash uint32, id uint64, packetId PacketId) (qnode, bnode *ListNode) {
	if buffer.head == nil {
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

	qnode = buffer.popFront()
	qnode.desc.timestamp = timestamp
	qnode.desc.hash = hash
	qnode.desc.id = id
	copy(qnode.desc.packetId[:], packetId[:])

	bnode = buffer.popFront()

	return qnode, bnode
}

func releaseToBuffer(qnode, bnode *ListNode) {
	buffer.pushBack(qnode)
	buffer.pushBack(bnode)
}

// 因为我们需要比较packetId来确认是否匹配，因此没有办法用库所提供的map或lru
type HashTable [HASH_TABLE_SIZE]*List

func withdraw(hash uint32, id uint64, packetId PacketId) bool {
	bucket := hashTable[compressHash(hash)]
	for bnode := bucket.head; bnode != nil; bnode = bnode.next {
		if bnode.desc.hash == hash && bnode.desc.id == id && bytes.Equal(bnode.desc.packetId[:], packetId[:]) {
			qnode := bnode.peer
			queue.remove(qnode)
			bucket.remove(bnode)
			releaseToBuffer(qnode, bnode)
			return true
		}
	}
	return false
}

func enQueue(qnode, bnode *ListNode) {
	if queue.size >= ELEMENTS_LIMIT {
		deQueue() // 无需记录此Counter，目前Hash空间不可能丢
	}
	key := compressHash(qnode.desc.hash)

	queue.pushBack(qnode)
	hashTable[key].pushBack(bnode)

	if hashTable[key].size > counter.MaxBucket {
		counter.MaxBucket = hashTable[key].size
	}
}

func deQueue() {
	qnode := queue.popFront()
	if qnode != nil {
		bnode := hashTable[compressHash(qnode.desc.hash)].popFront() // queue和bucket的第一个一定相同
		releaseToBuffer(qnode, bnode)
	}
	return
}

func deleteTimeout(timestamp time.Duration) {
	for queue.head != nil && timestamp-queue.head.desc.timestamp > ENTRY_TIMEOUT {
		counter.Timeout++
		deQueue()
	}
}

func lookup(hash uint32, id uint64, timestamp time.Duration, packetId PacketId) bool {
	deleteTimeout(timestamp)
	counter.Total++

	if withdraw(hash, id, packetId) {
		counter.Hit++
		return true
	}

	qnode, bnode := allocateNodePair(timestamp, hash, id, packetId)
	enQueue(qnode, bnode)
	return false
}

func init() {
	hashTable = &HashTable{}
	for i := 0; i < HASH_TABLE_SIZE; i++ {
		hashTable[i] = &List{}
	}
	stats.RegisterCountable("dedup", stats.EMPTY_TAG, counter)
}
