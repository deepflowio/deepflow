package pool

import (
	"unsafe"

	. "gitlab.x.lan/yunshan/droplet-libs/datastructure"
)

type pointer = unsafe.Pointer
type Option = interface{}
type OptionPoolSize int

const DEFAULT_POOL_SIZE = 65536

type LockFreePool struct {
	TreiberStack

	alloc func() interface{}
}

func (p *LockFreePool) Get() interface{} {
	if element := p.Pop(); element != nil {
		return element
	} else {
		return p.alloc()
	}
}

func (p *LockFreePool) Put(x interface{}) {
	p.Push(x)
}

func NewLockFreePool(alloc func() interface{}, options ...Option) LockFreePool {
	poolSize := DEFAULT_POOL_SIZE
	for _, opt := range options {
		if size, ok := opt.(OptionPoolSize); ok {
			poolSize = int(size)
		}
	}

	return LockFreePool{
		TreiberStack: NewTreiberStack(poolSize),
		alloc:        alloc,
	}
}
