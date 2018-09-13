/**
 * 哈希索引的多队列实现
 */
package queue

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

type FixedMultiQueue []Queue

func (q FixedMultiQueue) entry(key HashKey) Queue {
	return q[key&(uint8(len(q)-1))]
}

func (q FixedMultiQueue) Get(key HashKey) interface{} {
	return q.entry(key).Get()
}

func (q FixedMultiQueue) Gets(key HashKey, output []interface{}) int {
	return q.entry(key).Gets(output)
}

func (q FixedMultiQueue) Put(key HashKey, input ...interface{}) error {
	return q.entry(key).Put(input...)
}

func (q FixedMultiQueue) Len(key HashKey) int {
	return q.entry(key).Len()
}

/**
 * HashKey只会取部分低比特位，所以使用key时需要确保低位哈希均匀
 * table的大小和queue的数量并不等同，目的是支持hashKey的比特与操作而非除
 * 哈希的最大值可以通过len来获取
 */
func NewOverwriteQueues(module string, count uint8, queueSize int) FixedMultiQueue {
	size := int(count)
	queues := make([]Queue, size)
	for i := 0; i < size; i++ {
		tags := stats.OptionStatTags{"index": strconv.Itoa(i)}
		queue := new(OverwriteQueue)
		queue.Init(module, queueSize, tags)
		queues[i] = queue
	}
	tableSize := 16 // at least 16 entries
	for tableSize < size {
		tableSize <<= 1
	}
	table := make(FixedMultiQueue, tableSize)
	for i := 0; i < tableSize; i++ {
		table[i] = queues[i%size]
	}
	return table
}
