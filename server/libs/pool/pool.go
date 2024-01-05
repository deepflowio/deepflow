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

package pool

import (
	"math"
	"reflect"
	"sync"
	"sync/atomic"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("pool")

type Option = interface{}
type OptionPoolSizePerCPU int
type OptionInitFullPoolSize int // 太大会导致Get操作卡顿，太小会导致创建过多的slice
type OptionCounterNameSuffix string

const OPTIMAL_BLOCK_SIZE = 1 << 16
const POOL_SIZE_PER_CPU = OptionPoolSizePerCPU(256)
const INIT_FULL_POOL_SIZE = OptionInitFullPoolSize(256)

type Counter struct {
	Name             string
	ObjectSize       uint64
	PoolSizePerCPU   uint32
	InitFullPoolSize uint32
	closed           bool

	InUseObjects uint64 `statsd:"in_use_objects,gauge"`
	InUseBytes   uint64 `statsd:"in_use_bytes,gauge"`
}

func (c *Counter) GetCounter() interface{} {
	return c
}

func (c *Counter) Closed() bool {
	return c.closed
}

// 此Callback可用于为Counter添加statsd监控
type CounterRegisterCallback func(*Counter)

var (
	counterListLock         sync.Mutex
	counterRegisterCallback CounterRegisterCallback
	allCounters             []*Counter
)

func SetCounterRegisterCallback(callback CounterRegisterCallback) {
	counterListLock.Lock()
	counterRegisterCallback = callback
	for _, counter := range allCounters {
		counterRegisterCallback(counter)
	}
	counterListLock.Unlock()
}

// sync.Pool对于每一个系统线程，能够无锁提取存放一个元素，
// 其余元素会通过锁追加到数组中。为了能够尽可能避免锁的使用，
// 我们需要利用好这一个元素的位置，所以在这个元素上放置slice指针
// 作为实际的pool使用，每次Get/Put时，先拿到slice，弹出/推入元素后再
// 将slice放回，以尽可能无锁分配释放资源
type LockFreePool struct {
	emptyPool *sync.Pool
	fullPool  *sync.Pool

	counter *Counter
}

func (p *LockFreePool) Get() interface{} {
	atomic.AddUint64(&p.counter.InUseObjects, 1)
	atomic.AddUint64(&p.counter.InUseBytes, p.counter.ObjectSize)

	elemPool := p.fullPool.Get().(*[]interface{}) // avoid convT2Eslice
	pool := *elemPool
	e := pool[len(pool)-1]
	*elemPool = pool[:len(pool)-1]
	if len(pool) > 1 {
		p.fullPool.Put(elemPool)
	} else {
		p.emptyPool.Put(elemPool) // Empty, 还给别的CPU
	}
	return e
}

func (p *LockFreePool) Put(x interface{}) {
	atomic.AddUint64(&p.counter.InUseObjects, math.MaxUint64)
	atomic.AddUint64(&p.counter.InUseBytes, math.MaxUint64-p.counter.ObjectSize+1)

	pool := p.emptyPool.Get().(*[]interface{}) // avoid convT2Eslice
	*pool = append(*pool, x)
	if len(*pool) < cap(*pool) {
		p.emptyPool.Put(pool)
	} else {
		p.fullPool.Put(pool) // Full, 还给别的CPU
	}
}

// 注意OptionInitFullPoolSize不能大于OptionPoolSizePerCPU，且不能小于等于0
func NewLockFreePool(alloc func() interface{}, options ...Option) *LockFreePool {
	// options
	poolSizePerCPU := POOL_SIZE_PER_CPU
	initFullPoolSize := INIT_FULL_POOL_SIZE
	counterNameSuffix := ""
	for _, opt := range options {
		if size, ok := opt.(OptionPoolSizePerCPU); ok {
			poolSizePerCPU = size
		} else if size, ok := opt.(OptionInitFullPoolSize); ok {
			initFullPoolSize = size
		} else if suffixName, ok := opt.(OptionCounterNameSuffix); ok {
			counterNameSuffix = string(suffixName)
		}
	}
	if poolSizePerCPU < OptionPoolSizePerCPU(initFullPoolSize) || initFullPoolSize <= 0 {
		poolSizePerCPU = POOL_SIZE_PER_CPU
		initFullPoolSize = INIT_FULL_POOL_SIZE
	}
	objectType := reflect.Indirect(reflect.ValueOf(alloc())).Type()
	objectSize := uint64(objectType.Size())
	if len(options) == 0 { // automatically adjust pool size if no option is assigned
		optimalSize := uint64(OPTIMAL_BLOCK_SIZE) / objectSize
		if optimalSize > 4 && OptionPoolSizePerCPU(optimalSize) < POOL_SIZE_PER_CPU {
			poolSizePerCPU = OptionPoolSizePerCPU(optimalSize)
			initFullPoolSize = OptionInitFullPoolSize(optimalSize)
		}
	}

	// functions
	newEmptySlice := func() interface{} {
		p := make([]interface{}, 0, poolSizePerCPU)
		return &p
	}
	newFullSlice := func() interface{} {
		p := make([]interface{}, initFullPoolSize, poolSizePerCPU)
		for i := OptionInitFullPoolSize(0); i < initFullPoolSize; i++ {
			p[i] = alloc()
		}
		return &p
	}

	// counter
	counter := &Counter{
		Name:             objectType.String() + counterNameSuffix,
		ObjectSize:       objectSize,
		PoolSizePerCPU:   uint32(poolSizePerCPU),
		InitFullPoolSize: uint32(initFullPoolSize),
	}
	counterListLock.Lock()
	for _, c := range allCounters {
		if c.Name == counter.Name {
			c.closed = true // close old counter with the same objectType
		}
	}
	if counterRegisterCallback != nil {
		counterRegisterCallback(counter)
	}
	allCounters = append(allCounters, counter)
	counterListLock.Unlock()

	return &LockFreePool{
		emptyPool: &sync.Pool{
			New: newEmptySlice,
		},
		fullPool: &sync.Pool{
			New: newFullSlice,
		},
		counter: counter,
	}
}
