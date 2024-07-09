/*
 * Copyright (c) 2024 Yunshan Networks
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

package tracetree

import (
	"fmt"
	"net"

	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

const TRACE_TREE_VERSION = 0x11

type TraceTree struct {
	Time         uint32
	TraceidIndex uint64

	TraceId string

	SpanInfos []SpanInfo
}

type SpanInfo struct {
	IsIPv4           bool
	AutoServiceType0 uint8
	AutoServiceID0   uint32
	IP40             uint32
	IP60             net.IP
	AppService0      string

	AutoServiceType1 uint8
	AutoServiceID1   uint32
	IP41             uint32
	IP61             net.IP
	AppService1      string

	ResponseDuration uint64
	ResponseStatus   uint8
}

func (t *TraceTree) Release() {
	ReleaseTraceTree(t)
}

var poolTraceTree = pool.NewLockFreePool(func() interface{} {
	return new(TraceTree)
})

func AcquireTraceTree() *TraceTree {
	return poolTraceTree.Get().(*TraceTree)
}

func ReleaseTraceTree(t *TraceTree) {
	if t == nil {
		return
	}
	spanInfos := t.SpanInfos[:0]
	*t = TraceTree{}
	t.SpanInfos = spanInfos
	poolTraceTree.Put(t)
}

func (t *TraceTree) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU8(TRACE_TREE_VERSION)
	encoder.WriteString255(t.TraceId)
	encoder.WriteU16(uint16(len(t.SpanInfos)))
	for _, spanInfo := range t.SpanInfos {
		encoder.WriteBool(spanInfo.IsIPv4)
		encoder.WriteU8(spanInfo.AutoServiceType0)
		// ....
	}
}

func (t *TraceTree) Decode(decoder *codec.SimpleDecoder) error {
	version := decoder.ReadU8()
	if version != TRACE_TREE_VERSION {
		return fmt.Errorf("current data version is %d expect version is %d", version, TRACE_TREE_VERSION)
	}
	t.TraceId = decoder.ReadString255()
	spanCount := int(decoder.ReadU16())
	for i := 0; i < spanCount; i++ {
		t.SpanInfos = append(t.SpanInfos, SpanInfo{})
		t.SpanInfos[i].IsIPv4 = decoder.ReadBool()
		t.SpanInfos[i].AutoServiceType0 = decoder.ReadU8()
		// ....
	}
	if decoder.Failed() {
		return fmt.Errorf("decode failed, offset is %d, buf length is %d ", decoder.Offset(), len(decoder.Bytes()))
	}
	return nil
}
