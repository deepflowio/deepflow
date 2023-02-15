/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package datatype

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype/pb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

const (
	VERSION                   = 20220128
	LAST_SIMPLE_CODEC_VERSION = 20220111 // 这个版本及之前的版本使用simple_codec, 之后的版本使用pb_codec, 使用pb_codec在版本不匹配时，不丢数据
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

func (f *TaggedFlow) EncodePB(encoder *codec.SimpleEncoder, i interface{}) error {
	p, ok := i.(*pb.TaggedFlow)
	if !ok {
		return fmt.Errorf("invalid interface type, should be *pb.TaggedFlow")
	}
	// 传入的的p *pb.TaggedFlow是可复用的，若p.FlowPerfStats无须发送，会被置为空，故先保留，使可复用
	var flowPerfStats *pb.FlowPerfStats
	if p.Flow != nil {
		flowPerfStats = p.Flow.PerfStats
	}
	f.WriteToPB(p)
	encoder.WritePB(p)
	if p.Flow.PerfStats == nil {
		p.Flow.PerfStats = flowPerfStats
	}
	return nil
}

func (f *TaggedFlow) WriteToPB(p *pb.TaggedFlow) error {
	if p.Flow == nil {
		p.Flow = &pb.Flow{}
	}
	f.Flow.WriteToPB(p.Flow)
	// f.Tag.Encode(encoder)  // 目前无需发送,不encode
	return nil
}

func (f *TaggedFlow) Release() {
	ReleaseTaggedFlow(f)
}

func (f *TaggedFlow) Reverse() {
	f.Flow.Reverse()
	f.Tag.Reverse()
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

	if taggedFlow.FlowPerfStats != nil {
		ReleaseFlowPerfStats(taggedFlow.FlowPerfStats)
		taggedFlow.FlowPerfStats = nil
	}
	*taggedFlow = TaggedFlow{}
	taggedFlowPool.Put(taggedFlow)
}

// 注意：不拷贝FlowPerfStats
func CloneTaggedFlowForPacketStat(taggedFlow *TaggedFlow) *TaggedFlow {
	newTaggedFlow := AcquireTaggedFlow()
	*newTaggedFlow = *taggedFlow
	newTaggedFlow.FlowPerfStats = nil
	newTaggedFlow.ReferenceCount.Reset()
	return newTaggedFlow
}

func CloneTaggedFlow(taggedFlow *TaggedFlow) *TaggedFlow {
	newTaggedFlow := AcquireTaggedFlow()
	*newTaggedFlow = *taggedFlow
	newTaggedFlow.ReferenceCount.Reset()
	if taggedFlow.FlowPerfStats != nil {
		newTaggedFlow.FlowPerfStats = CloneFlowPerfStats(taggedFlow.FlowPerfStats)
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

func DecodePB(decoder *codec.SimpleDecoder, t *pb.TaggedFlow) {
	decoder.ReadPB(t)
}
