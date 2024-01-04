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

/**
 * 参照github.com/Workiva/go-datastructures的PriorityQueue实现
 * 区别主要是，PriorityQueue通过优先级来决定放置到队首或队尾，但是此Queue
 * 是固定长度队列，新的数据会覆盖旧的数据，并且没有优先级比较的过程。
 */
package queue

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var OverflowError = errors.New("Requested size is larger than capacity")

type Counter struct {
	In          uint64 `statsd:"in,count"`
	Out         uint64 `statsd:"out,count"`
	Overwritten uint64 `statsd:"overwritten,count"`
	Pending     uint64 `statsd:"pending,gauge"`
}

type OverwriteQueue struct {
	utils.Closable
	sync.Mutex

	writeLock     sync.Mutex
	readerWaiting int
	reader        sync.WaitGroup
	items         []interface{}
	size          uint // power of 2
	writeCursor   uint
	pending       uint
	release       func(x interface{})

	counter *Counter
}

const MAX_BATCH_GET_SIZE = 1 << 16

var nilArrayForInit [MAX_BATCH_GET_SIZE]interface{}

func NewOverwriteQueue(name string, size int, options ...Option) *OverwriteQueue {
	queue := &OverwriteQueue{}
	queue.Init(name, size, options...)
	return queue
}

func (q *OverwriteQueue) Init(name string, size int, options ...Option) {
	if q.size != 0 {
		return
	}

	var flushIndicator time.Duration
	statOptions := []stats.Option{stats.OptionStatTags{"module": name}}
	var module string
	for _, option := range options {
		switch option.(type) {
		case OptionRelease:
			q.release = option.(OptionRelease)
		case OptionFlushIndicator:
			flushIndicator = option.(OptionFlushIndicator)
		case OptionModule:
			module = option.(OptionModule)
		case OptionStatsOption: // XXX: interface{}类型，必须放在最后
			statOptions = append(statOptions, option.(OptionStatsOption))
		default:
			panic(fmt.Sprintf("Unknown option %v", option))
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
	stats.RegisterCountableWithModulePrefix(module, "queue", q, statOptions...)

	if flushIndicator > 0 {
		go func() {
			for range time.NewTicker(flushIndicator).C {
				q.Put(nil)
				if q.Closed() {
					break
				}
			}
		}()
	}
}

func (q *OverwriteQueue) GetCounter() interface{} {
	var counter *Counter
	counter, q.counter = q.counter, &Counter{}
	return counter
}

func (q *OverwriteQueue) firstIndex() uint {
	return (q.writeCursor + q.size - q.pending) & (q.size - 1)
}

// 获取队列等待处理的元素数量
func (q *OverwriteQueue) Len() int {
	return int(q.pending)
}

func (q *OverwriteQueue) releaseOverwritten(overwritten []interface{}) {
	for _, toRelease := range overwritten {
		if toRelease != nil { // when flush indicator enabled
			q.release(toRelease)
		}
	}
}

// 放置单个/多个元素，注意不要超过Size、不能放置空列表
func (q *OverwriteQueue) Put(items ...interface{}) error {
	itemSize := uint(len(items))
	if itemSize > q.size {
		return OverflowError
	}

	q.writeLock.Lock()

	freeSize := q.size - q.pending
	locked := false
	// q.pending的增长由writeLock保护，q.pending的减少虽然非线程安全，
	// 但滞后的q.pending的减少反而会倾向于导致进入此分支，因此是安全的
	if itemSize > freeSize {
		locked = true
		q.Lock()
		freeSize = q.size - q.pending
		if q.release != nil && itemSize > freeSize { // 需要再次判断确认是否需要释放
			releaseFrom, releaseTo := q.firstIndex(), q.writeCursor+itemSize
			if releaseTo > q.size {
				releaseTo = releaseTo & (q.size - 1)
			}
			if releaseFrom <= releaseTo {
				q.releaseOverwritten(q.items[releaseFrom:releaseTo])
			} else {
				q.releaseOverwritten(q.items[releaseFrom:q.size])
				q.releaseOverwritten(q.items[:releaseTo])
			}
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
	q.pending = utils.UintMin(q.pending+itemSize, q.size)
	q.writeCursor = (q.writeCursor + itemSize) & (q.size - 1)
	if q.readerWaiting > 0 {
		q.readerWaiting--
		q.Unlock()
		q.reader.Done()
	} else {
		q.Unlock()
	}

	if q.counter.Pending < uint64(q.pending) {
		q.counter.Pending = uint64(q.pending)
	}

	q.writeLock.Unlock()
	return nil
}

func (q *OverwriteQueue) get() interface{} {
	first := q.firstIndex()
	item := q.items[first]
	q.items[first] = nil
	q.pending--
	q.counter.Out++
	return item
}

// 获取单个队列中的元素。当队列为空时将会阻塞等待
func (q *OverwriteQueue) Get() interface{} { // will block
	q.Lock()
	if q.pending == 0 {
		q.reader.Add(1)
		q.readerWaiting++
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
	size := utils.UintMin(uint(len(output)), q.pending)
	output = output[:size]
	first := q.firstIndex()
	copied := copy(output, q.items[first:])
	copy(q.items[first:], nilArrayForInit[:copied])
	if uint(copied) != size {
		copied = copy(output[copied:], q.items)
		copy(q.items, nilArrayForInit[:copied])
	}
	q.pending -= size
	q.counter.Out += uint64(size)
	return int(size)
}

// 获取多个队列中的元素，传入的slice会被覆盖写入，队列为空时阻塞等待
// 写入的数量是slice的length而不是capacity
func (q *OverwriteQueue) Gets(output []interface{}) int { // will block
	if len(output) > MAX_BATCH_GET_SIZE {
		panic("一次获取的数量太多")
	}
	q.Lock()
	if q.pending == 0 {
		q.reader.Add(1)
		q.readerWaiting++
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
