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
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

var OverflowError = errors.New("Requested size is larger than capacity")

type Counter struct {
	In          uint64 `statsd:"in,count"`
	Out         uint64 `statsd:"out,count"`
	Overwritten uint64 `statsd:"overwritten,count"`
	Pending     uint64 `statsd:"pending,gauge"`
}

type OverwriteQueue struct {
	sync.Mutex

	writeLock     sync.Mutex
	readerWaiting bool
	reader        sync.WaitGroup
	items         []interface{}
	size          uint // power of 2
	writeCursor   uint
	pending       uint
	release       func(x interface{})

	counter *Counter
}

func NewOverwriteQueue(module string, size int, options ...Option) *OverwriteQueue {
	queue := &OverwriteQueue{}
	queue.Init(module, size, options...)
	return queue
}

func (q *OverwriteQueue) Init(module string, size int, options ...Option) {
	if q.size != 0 {
		return
	}

	var flushIndicator time.Duration
	statOptions := []stats.StatsOption{stats.OptionStatTags{"module": module}}
	for _, option := range options {
		switch option.(type) {
		case OptionRelease:
			q.release = option.(OptionRelease)
		case OptionFlushIndicator:
			flushIndicator = option.(OptionFlushIndicator)
		case OptionStatsOption: // XXX: interface{}类型，必须放在最后
			statOptions = append(statOptions, option.(OptionStatsOption))
		default:
			continue
		}
	}

	for i := 0; i < 32; i++ {
		if 1<<uint(i) >= size {
			size = 1 << uint(i)
			break
		}
	}
	q.items = make([]interface{}, size)
	q.size = uint(size)
	q.counter = &Counter{}
	stats.RegisterCountable("queue", q, statOptions...)
	runtime.SetFinalizer(q, func(q *OverwriteQueue) { q.Close() })

	if flushIndicator > 0 {
		go func() {
			for range time.NewTicker(flushIndicator).C {
				q.Put(nil)
			}
		}()
	}
}

func (q *OverwriteQueue) GetCounter() interface{} {
	var counter *Counter
	counter, q.counter = q.counter, &Counter{}
	return counter
}

func (q *OverwriteQueue) Close() {
	stats.DeregisterCountable(q)
}

func (q *OverwriteQueue) firstIndex() uint {
	return (q.writeCursor + q.size - q.pending) & (q.size - 1)
}

// 获取队列等待处理的元素数量
func (q *OverwriteQueue) Len() int {
	return int(q.pending)
}

func (q *OverwriteQueue) releaseOverwritten(overwritten []interface{}) {
	if q.release != nil && q.pending == q.size {
		for _, toRelease := range overwritten {
			if toRelease != nil { // when flush indicator enabled
				q.release(toRelease)
			}
		}
	}
}

// 放置单个/多个元素
func (q *OverwriteQueue) Put(items ...interface{}) error {
	itemSize := uint(len(items))
	if itemSize > q.size {
		return OverflowError
	}

	q.writeLock.Lock()

	freeSize := (q.size - q.pending)
	locked := false
	if itemSize > freeSize {
		locked = true
		q.Lock()
		if q.writeCursor+itemSize <= q.size {
			q.releaseOverwritten(q.items[q.writeCursor : q.writeCursor+itemSize])
		} else {
			q.releaseOverwritten(q.items[q.writeCursor:q.size])
			q.releaseOverwritten(q.items[:itemSize-(q.size-q.writeCursor)])
		}
	}

	if copied := copy(q.items[q.writeCursor:], items); uint(copied) != itemSize {
		copy(q.items, items[copied:])
	}

	q.counter.In += uint64(itemSize)
	if itemSize > freeSize {
		q.counter.Overwritten += uint64(itemSize - freeSize)
	}

	if !locked {
		q.Lock()
	}
	q.pending = UintMin(q.pending+itemSize, q.size)
	q.writeCursor = (q.writeCursor + itemSize) & (q.size - 1)
	q.Unlock()

	if q.counter.Pending < uint64(q.pending) {
		q.counter.Pending = uint64(q.pending)
	}

	if q.readerWaiting {
		q.readerWaiting = false
		q.reader.Done()
	}
	q.writeLock.Unlock()
	return nil
}

func (q *OverwriteQueue) get() interface{} {
	items := q.items[q.firstIndex()]
	q.pending--
	q.counter.Out++
	return items
}

// 获取单个队列中的元素。当队列为空时将会阻塞等待
func (q *OverwriteQueue) Get() interface{} { // will block
	q.Lock()
	if q.pending == 0 {
		q.reader.Add(1)
		q.readerWaiting = true
		q.Unlock()
		q.reader.Wait()
		q.Lock()
		item := q.get()
		q.Unlock()
		return item
	}
	item := q.get()
	q.Unlock()
	return item
}

func (q *OverwriteQueue) gets(output []interface{}) int {
	size := UintMin(uint(len(output)), q.pending)
	output = output[:size]
	first := uint(q.firstIndex())
	copied := copy(output, q.items[first:])
	if uint(copied) != size {
		copy(output[copied:], q.items)
	}
	q.pending -= size
	q.counter.Out += uint64(size)
	return int(size)
}

// 获取多个队列中的元素，传入的slice会被覆盖写入，队列为空时阻塞等待
// 写入的数量是slice的length而不是capacity
func (q *OverwriteQueue) Gets(output []interface{}) int { // will block
	q.Lock()
	if q.pending == 0 {
		q.reader.Add(1)
		q.readerWaiting = true
		q.Unlock()
		q.reader.Wait()
		q.Lock()
		size := q.gets(output)
		q.Unlock()
		return size
	}
	size := q.gets(output)
	q.Unlock()
	return int(size)
}
