package datatype

import (
	"sync"
)

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
	*pool = append(*pool, x)
	p.Pool.Put(pool)
}

// 通过返回值赋值省去Init方法
func NewLockFreePool(alloc func() interface{}) (pool LockFreePool) {
	pool.New = func() interface{} {
		p := make([]interface{}, 0, 1024) // assuming about 1024 elements to cache
		return &p
	}
	pool.alloc = alloc
	return
}
