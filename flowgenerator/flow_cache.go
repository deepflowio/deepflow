package flowgenerator

import (
	"sync"
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
