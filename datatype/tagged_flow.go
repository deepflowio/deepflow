package datatype

import (
	"fmt"
	"sync"
)

type TaggedFlow struct {
	Flow
	Tag
}

var taggedFlowPool = sync.Pool{
	New: func() interface{} {
		return new(TaggedFlow)
	},
}

func AcquireTaggedFlow() *TaggedFlow {
	return taggedFlowPool.Get().(*TaggedFlow)
}

func ReleaseTaggedFlow(taggedFlow *TaggedFlow) {
	if taggedFlow.TcpPerfStats != nil {
		ReleaseTcpPerfStats(taggedFlow.TcpPerfStats)
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

func CloneTaggedFlowHelper(items []interface{}) []interface{} {
	newItems := make([]interface{}, len(items))
	for i, e := range items {
		taggedFlow := e.(*TaggedFlow)
		newItems[i] = CloneTaggedFlow(taggedFlow)
	}
	return newItems
}

func (f *TaggedFlow) String() string {
	return fmt.Sprintf("Flow: %s, Tag: %+v", f.Flow.String(), f.Tag)
}
