/**
 * 参照github.com/golang-collections/go-datastructures的PriorityQueue实现
 * 区别主要是，PriorityQueue通过优先级来决定放置到队首或队尾，但是此Queue
 * 是固定长度队列，新的数据会覆盖旧的数据，并且没有优先级比较的过程。
 */
package queue

import (
	"errors"
	"runtime"
	"sync"

	"gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

var OverflowError = errors.New("Requested size is larger than capacity")

type Transaction struct {
	request, response sync.WaitGroup
}

type Counter struct {
	in          uint64
	out         uint64
	overwritten uint64
}

type OverwriteQueue struct { // XXX: use circle array
	sync.Mutex
	Counter

	items    []interface{}
	waiting  []Transaction
	size     uint // power of 2
	putIndex uint
	pending  uint
}

func NewOverwriteQueue(module string, size int) Queue {
	queue := &OverwriteQueue{}
	queue.Init(module, size)
	return queue
}

func (q *OverwriteQueue) Init(module string, size int) {
	if q.size != 0 {
		return
	}

	for i := 0; i < 32; i++ {
		if 1<<uint(i) >= size {
			size = 1 << uint(i)
			break
		}
	}
	q.items = make([]interface{}, size)
	q.waiting = make([]Transaction, 0, 10)
	q.size = uint(size)
	stats.RegisterCountable(module, q)
	runtime.SetFinalizer(q, func(q *OverwriteQueue) { q.Release() })
}

func (q *OverwriteQueue) GetCounter() interface{} {
	q.Lock()
	statItems := []stats.StatItem{
		stats.StatItem{"pending", stats.GAUGE_TYPE, q.pending},
		stats.StatItem{"overwritten", stats.COUNT_TYPE, q.overwritten},
		stats.StatItem{"in", stats.COUNT_TYPE, q.in},
		stats.StatItem{"out", stats.COUNT_TYPE, q.out},
	}
	q.Counter = Counter{}
	q.Unlock()
	return statItems
}

func (q *OverwriteQueue) Release() {
	stats.DeregisterCountable(q)
}

func (q *OverwriteQueue) firstIndex() uint {
	return (q.putIndex + q.size - q.pending) & (q.size - 1)
}

// 获取队列等待处理的元素数量
func (q *OverwriteQueue) Len() int {
	return int(q.pending)
}

// 放置单个/多个元素
func (q *OverwriteQueue) Put(items ...interface{}) error {
	itemSize := uint(len(items))
	if itemSize > q.size {
		return OverflowError
	}

	q.Lock()
	q.in += uint64(itemSize)
	if copied := copy(q.items[q.putIndex:], items); uint(copied) != itemSize {
		copy(q.items, items[copied:])
	}

	freeSize := (q.size - q.pending)
	if itemSize > freeSize {
		q.overwritten += uint64(itemSize - freeSize)
	}

	q.pending = UintMin(q.pending+itemSize, q.size)
	q.putIndex = (q.putIndex + itemSize) & (q.size - 1)
	for len(q.waiting) > 0 {
		wait := &q.waiting[len(q.waiting)-1]
		q.waiting = q.waiting[:len(q.waiting)-1]
		wait.response.Add(1)
		wait.request.Done()
		wait.response.Wait()
		if q.pending == 0 {
			break
		}
	}
	q.Unlock()
	return nil
}

func (q *OverwriteQueue) get() interface{} {
	items := q.items[q.firstIndex()]
	q.pending--
	q.out++
	return items
}

// 获取单个队列中的元素。当队列为空时将会阻塞等待
func (q *OverwriteQueue) Get() interface{} { // will block
	q.Lock()
	if q.pending == 0 {
		q.waiting = append(q.waiting, Transaction{})
		wait := &q.waiting[len(q.waiting)-1]
		wait.request.Add(1)
		q.Unlock()
		wait.request.Wait()
		// 不需要重新拿锁，因为Put正在阻塞等待Complete
		item := q.get()
		wait.response.Done()
		return item
	}
	item := q.get()
	q.Unlock()
	return item
}

func (q *OverwriteQueue) gets(output []interface{}) uint {
	size := UintMin(uint(len(output)), q.pending)
	output = output[:size]
	first := uint(q.firstIndex())
	copied := copy(output, q.items[first:])
	if uint(copied) != size {
		copy(output[copied:], q.items)
	}
	q.pending -= size
	q.out += uint64(size)
	return size
}

// 获取多个队列中的元素，传入的slice会被覆盖写入，队列为空时阻塞等待
// 写入的数量是slice的length而不是capacity
func (q *OverwriteQueue) Gets(output []interface{}) int { // will block
	q.Lock()
	if q.pending == 0 {
		q.waiting = append(q.waiting, Transaction{})
		wait := &q.waiting[len(q.waiting)-1]
		wait.request.Add(1)
		q.Unlock()
		wait.request.Wait()
		// 不需要重新拿锁，因为Put正在阻塞等待Complete
		size := q.gets(output)
		wait.response.Done()
		return int(size)
	}
	size := q.gets(output)
	q.Unlock()
	return int(size)
}
