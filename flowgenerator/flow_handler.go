package flowgenerator

import (
	"runtime"
	"sync"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type FlowCache struct {
	sync.Mutex

	capacity int
	flowList *ListFlowExtra
}

func (f *FlowCache) SafeFlowListRemove(e *ElementFlowExtra) *FlowExtra {
	f.Lock()
	flowExtra := f.flowList.Remove(e)
	f.Unlock()
	return flowExtra
}

func (f *FlowCache) SafeFlowListRemoveFront() *ElementFlowExtra {
	f.Lock()
	elementFlowExtra := f.flowList.RemoveFront()
	f.Unlock()
	return elementFlowExtra
}

func (f *FlowCache) SafeFlowListPushFront(v *FlowExtra) *ElementFlowExtra {
	f.Lock()
	elementFlowExtra := f.flowList.PushFront(v)
	f.Unlock()
	return elementFlowExtra
}

type FlowCacheHashMap struct {
	hashMap            []*FlowCache
	hashBasis          uint32
	mapSize            uint64
	timeoutParallelNum uint64
}

const BLOCK_SIZE = 32

type TaggedFlowHandler struct {
	sync.Pool

	block       *[BLOCK_SIZE]TaggedFlow
	blockCursor int
	getNum      uint32
	putNum      uint32
}

func (h *TaggedFlowHandler) Init() *TaggedFlowHandler {
	gc := func(b *[BLOCK_SIZE]TaggedFlow) {
		*b = [BLOCK_SIZE]TaggedFlow{}
		h.putNum++
		h.Put(b)
	}
	h.Pool.New = func() interface{} {
		block := new([BLOCK_SIZE]TaggedFlow)
		runtime.SetFinalizer(block, gc)
		return block
	}
	h.block = h.Get().(*[BLOCK_SIZE]TaggedFlow)
	h.getNum++
	return h
}

func (h *TaggedFlowHandler) alloc() *TaggedFlow {
	taggedFlow := &h.block[h.blockCursor]
	h.blockCursor++
	if h.blockCursor >= len(*h.block) {
		h.block = h.Get().(*[BLOCK_SIZE]TaggedFlow)
		h.getNum++
		h.blockCursor = 0
	}
	return taggedFlow
}

type FlowExtraHandler struct {
	sync.Pool

	block       *[BLOCK_SIZE]FlowExtra
	blockCursor int
}

func (h *FlowExtraHandler) Init() *FlowExtraHandler {
	gc := func(b *[BLOCK_SIZE]FlowExtra) {
		*b = [BLOCK_SIZE]FlowExtra{}
		h.Put(b)
	}
	h.Pool.New = func() interface{} {
		block := new([BLOCK_SIZE]FlowExtra)
		runtime.SetFinalizer(block, gc)
		return block
	}
	h.block = h.Get().(*[BLOCK_SIZE]FlowExtra)
	return h
}

func (h *FlowExtraHandler) alloc() *FlowExtra {
	flowExtra := &h.block[h.blockCursor]
	h.blockCursor++
	if h.blockCursor >= len(*h.block) {
		h.block = h.Get().(*[BLOCK_SIZE]FlowExtra)
		h.blockCursor = 0
	}
	return flowExtra
}
