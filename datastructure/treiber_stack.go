package datastructure

import (
	"math"
	"sync/atomic"
)

type Tag = uint64 // stamp, index

// 为避免出现ABA问题(参考维基百科ABA problem)，
// TreiberStack实现为固定长度的栈，以能够在CAS操作时附带stamp
// TODO: https://github.com/tmthrgd/atomic128 实现了128bit的CAS，
//       虽然只能够支持x86。如果有需要的话，可以导入并使用，
//       或参考并实现StampedCompareAndSwapPointer
type TreiberStack struct {
	entries []Element
	top     Tag
	free    Tag
}

func (s *TreiberStack) pop(pointer *Tag) uint32 {
	for {
		tag := atomic.LoadUint64(pointer)
		stamp, index := uint32(tag>>32), uint32(tag)
		if index == math.MaxUint32 {
			return math.MaxUint32
		}

		nextIndex := uint32(uintptr(p(s.entries[index].Next)))
		newTag := uint64(stamp)<<32 | uint64(nextIndex)
		if atomic.CompareAndSwapUint64(pointer, tag, newTag) {
			return index
		}
	}
}

func (s *TreiberStack) push(pointer *Tag, index uint32) {
	for {
		tag := atomic.LoadUint64(pointer)
		stamp, topIndex := uint32(tag>>32), uint32(tag)
		s.entries[index].Next = (*Element)(p(uintptr(topIndex)))
		newTag := uint64(stamp+1)<<32 | uint64(index)
		if atomic.CompareAndSwapUint64(pointer, tag, newTag) {
			return
		}
	}
}

func (s *TreiberStack) Push(x interface{}) {
	index := s.pop(&s.free)
	if index == math.MaxUint32 {
		return
	}
	entry := &s.entries[index]
	entry.Value = x
	atomic.StorePointer((*p)(p(&entry.Value)), *(*p)(p(&entry.Value))) // wmb
	s.push(&s.top, index)
}

func (s *TreiberStack) Pop() interface{} {
	index := s.pop(&s.top)
	if index == math.MaxUint32 {
		return nil
	}
	entry := &s.entries[index]
	_ = atomic.LoadPointer((*p)(p(&entry.Value))) // rmb
	x := entry.Value
	s.push(&s.free, index)
	return x
}

func (s *TreiberStack) Init(entries []Element) {
	for i := 0; i < len(entries)-1; i++ {
		entries[i].Next = (*Element)(p(uintptr(i + 1)))
	}
	entries[len(entries)-1].Next = (*Element)(p(uintptr(math.MaxUint32)))
	s.entries = entries
	s.top = math.MaxUint32
}

func NewTreiberStack(size int) TreiberStack {
	stack := TreiberStack{}
	stack.Init(make([]Element, size))
	return stack
}
