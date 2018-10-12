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
	*taggedFlow = TaggedFlow{}
	taggedFlowPool.Put(taggedFlow)
}

func CloneTaggedFlow(taggedFlow *TaggedFlow) *TaggedFlow {
	newTaggedFlow := taggedFlowPool.Get().(*TaggedFlow)
	*newTaggedFlow = *taggedFlow
	return newTaggedFlow
}

func CloneTaggedFlowHelper(items []interface{}) []interface{} {
	newItems := make([]interface{}, len(items))
	for i, e := range items {
		taggedFlow := e.(*TaggedFlow)
		item := taggedFlowPool.Get().(*TaggedFlow)
		*item = *taggedFlow
		newItems[i] = item
	}
	return newItems
}

func (f *TaggedFlow) String() string {
	return fmt.Sprintf("Flow: %s, Tag: %+v", f.Flow.String(), f.Tag)
}
