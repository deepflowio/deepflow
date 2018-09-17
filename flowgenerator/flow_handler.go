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

type TaggedFlowBlock = [1024]TaggedFlow

type TaggedFlowHandler struct {
	sync.Pool

	block       *TaggedFlowBlock
	blockCursor int
}

func (h *TaggedFlowHandler) Init() *TaggedFlowHandler {
	gc := func(b *TaggedFlowBlock) {
		*b = TaggedFlowBlock{}
		h.Put(b)
	}
	h.Pool.New = func() interface{} {
		block := new(TaggedFlowBlock)
		runtime.SetFinalizer(block, gc)
		return block
	}
	h.block = h.Get().(*TaggedFlowBlock)
	return h
}

func (h *TaggedFlowHandler) alloc() *TaggedFlow {
	taggedFlow := &h.block[h.blockCursor]
	h.blockCursor++
	if h.blockCursor >= len(*h.block) {
		h.block = h.Get().(*TaggedFlowBlock)
		h.blockCursor = 0
	}
	return taggedFlow
}

type FlowExtraBlock = [1024]FlowExtra

type FlowExtraHandler struct {
	sync.Pool

	block       *FlowExtraBlock
	blockCursor int
}

func (h *FlowExtraHandler) Init() *FlowExtraHandler {
	gc := func(b *FlowExtraBlock) {
		*b = FlowExtraBlock{}
		h.Put(b)
	}
	h.Pool.New = func() interface{} {
		block := new(FlowExtraBlock)
		runtime.SetFinalizer(block, gc)
		return block
	}
	h.block = h.Get().(*FlowExtraBlock)
	return h
}

func (h *FlowExtraHandler) alloc() *FlowExtra {
	flowExtra := &h.block[h.blockCursor]
	h.blockCursor++
	if h.blockCursor >= len(*h.block) {
		h.block = h.Get().(*FlowExtraBlock)
		h.blockCursor = 0
	}
	return flowExtra
}
