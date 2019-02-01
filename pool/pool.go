package pool

import (
	"sync"
)

type Option = interface{}
type OptionPoolSizePerCPU int

const POOL_SIZE_PER_CPU = OptionPoolSizePerCPU(256)

// sync.Pool对于每一个系统线程，能够无锁提取存放一个元素，
// 其余元素会通过锁追加到数组中。为了能够尽可能避免锁的使用，
// 我们需要利用好这一个元素的位置，所以在这个元素上放置slice指针
// 作为实际的pool使用，每次Get/Put时，先拿到slice，弹出/推入元素后再
// 将slice放回，以尽可能无锁分配释放资源
type LockFreePool struct {
	sync.Pool

	alloc func() interface{}
}

func (p *LockFreePool) Get() interface{} {
	elemPool := p.Pool.Get().(*[]interface{}) // avoid convT2Eslice
	pool := *elemPool
	var e interface{}
	if len(pool) > 0 {
		e = pool[len(pool)-1]
		*elemPool = pool[:len(pool)-1]
	} else {
		e = p.alloc()
	}
	p.Pool.Put(elemPool)
	return e
}

func (p *LockFreePool) Put(x interface{}) {
	pool := p.Pool.Get().(*[]interface{}) // avoid convT2Eslice
	if len(*pool) < cap(*pool) {
		*pool = append(*pool, x)
	}
	p.Pool.Put(pool)
}

func NewLockFreePool(alloc func() interface{}, options ...Option) LockFreePool {
	poolSizePerCPU := POOL_SIZE_PER_CPU
	for _, opt := range options {
		if size, ok := opt.(OptionPoolSizePerCPU); ok {
			poolSizePerCPU = size
		}
	}
	newSlice := func() interface{} {
		p := make([]interface{}, 0, poolSizePerCPU)
		return &p
	}
	return LockFreePool{
		Pool: sync.Pool{
			New: newSlice,
		},
		alloc: alloc,
	}
}
