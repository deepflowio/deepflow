package datatype

import (
	"fmt"
	"sync"
	"sync/atomic"
)

type TaggedFlow struct {
	Flow
	Tag

	ExtraRefCount int32 // for PseudoClone
}

var taggedFlowPool = sync.Pool{
	New: func() interface{} { return new(TaggedFlow) },
}

func AcquireTaggedFlow() *TaggedFlow {
	return taggedFlowPool.Get().(*TaggedFlow)
}

func ReleaseTaggedFlow(taggedFlow *TaggedFlow) {
	if atomic.AddInt32(&taggedFlow.ExtraRefCount, -1) >= 0 {
		return
	}

	if taggedFlow.TcpPerfStats != nil {
		ReleaseTcpPerfStats(taggedFlow.TcpPerfStats)
		taggedFlow.TcpPerfStats = nil
	}
	*taggedFlow = TaggedFlow{}
	taggedFlowPool.Put(taggedFlow)
}

func CloneTaggedFlow(taggedFlow *TaggedFlow) *TaggedFlow {
	newTaggedFlow := AcquireTaggedFlow()
	*newTaggedFlow = *taggedFlow
	if taggedFlow.TcpPerfStats != nil {
		newTaggedFlow.TcpPerfStats = CloneTcpPerfStats(taggedFlow.TcpPerfStats)
	}
	return newTaggedFlow
}

func PseudoCloneTaggedFlow(taggedFlow *TaggedFlow) {
	atomic.AddInt32(&taggedFlow.ExtraRefCount, 1)
}

func PseudoCloneTaggedFlowHelper(items []interface{}) {
	for _, e := range items {
		PseudoCloneTaggedFlow(e.(*TaggedFlow))
	}
}

func (f *TaggedFlow) String() string {
	return fmt.Sprintf("Flow: %s, Tag: %+v", f.Flow.String(), f.Tag)
}
