package datatype

import (
	"fmt"

	"gitlab.x.lan/yunshan/droplet-libs/pool"
)

type TaggedFlow struct {
	Flow
	Tag

	pool.ReferenceCount
}

var taggedFlowPool = pool.NewLockFreePool(func() interface{} {
	return new(TaggedFlow)
})

func AcquireTaggedFlow() *TaggedFlow {
	f := taggedFlowPool.Get().(*TaggedFlow)
	f.ReferenceCount.Reset()
	return f
}

func ReleaseTaggedFlow(taggedFlow *TaggedFlow) {
	if taggedFlow.SubReferenceCount() {
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
	newTaggedFlow.ReferenceCount.Reset()
	if taggedFlow.TcpPerfStats != nil {
		newTaggedFlow.TcpPerfStats = CloneTcpPerfStats(taggedFlow.TcpPerfStats)
	}
	return newTaggedFlow
}

func PseudoCloneTaggedFlowHelper(items []interface{}) {
	for _, e := range items {
		e.(*TaggedFlow).AddReferenceCount()
	}
}

func (f *TaggedFlow) String() string {
	return fmt.Sprintf("%s\n\tTag: %+v", f.Flow.String(), f.Tag)
}
