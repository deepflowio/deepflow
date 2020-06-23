package datatype

import (
	"fmt"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
)

const (
	VERSION = 20200623
)

type TaggedFlow struct {
	Flow
	Tag

	pool.ReferenceCount
}

func (f *TaggedFlow) SequentialMerge(rhs *TaggedFlow) {
	f.Flow.SequentialMerge(&rhs.Flow)
	// f.Tag.SequentialMerge(rhs.Tag)  // 目前无需发送,不merge
}

func (f *TaggedFlow) Encode(encoder *codec.SimpleEncoder) error {
	f.Flow.Encode(encoder)
	// f.Tag.Encode(encoder)  // 目前无需发送,不encode
	return nil
}

func (f *TaggedFlow) Decode(decoder *codec.SimpleDecoder) {
	f.Flow.Decode(decoder)
	// f.Tag.Decode(decoder)
}

func (f *TaggedFlow) Release() {
	ReleaseTaggedFlow(f)
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

// 注意：不拷贝TcpPerfStats
func CloneTaggedFlowForPacketStat(taggedFlow *TaggedFlow) *TaggedFlow {
	newTaggedFlow := AcquireTaggedFlow()
	*newTaggedFlow = *taggedFlow
	newTaggedFlow.TcpPerfStats = nil
	newTaggedFlow.ReferenceCount.Reset()
	return newTaggedFlow
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
