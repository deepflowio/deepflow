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

	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const TRACE_TREE_VERSION = 0x11

func HashSearchIndex(key string) uint64 {
	return utils.DJBHash(17, key)
}

type TraceTree struct {
	Time        uint32
	SearchIndex uint64
	OrgId       uint16

	TraceId   string
	SpanInfos []SpanInfo

	encodedSpans []byte
}

type SpanInfo struct {
	AutoServiceType0 uint8
	AutoServiceType1 uint8
	AutoServiceID0   uint32
	AutoServiceID1   uint32
	AppService0      string
	AppService1      string
	Topic            string

	IsIPv4 bool
	IP40   uint32
	IP60   net.IP
	IP41   uint32
	IP61   net.IP

	Level0 uint8
	Level1 uint8

	ResponseDurationSum            uint64
	ResponseTotal                  uint32
	ResponseStatusServerErrorCount uint32
}

func (t *TraceTree) Release() {
	ReleaseTraceTree(t)
}

func (t *TraceTree) OrgID() uint16 {
	return t.OrgId
}

func (t *TraceTree) WriteBlock(block *ckdb.Block) {
	t.Encode()
	block.WriteDateTime(t.Time)
	block.Write(
		t.SearchIndex,
		t.TraceId,
		utils.String(t.encodedSpans),
	)
}

func TraceTreeColumns() []*ckdb.Column {
	return []*ckdb.Column{
		ckdb.NewColumn("time", ckdb.DateTime),
		ckdb.NewColumn("search_index", ckdb.UInt64),
		ckdb.NewColumn("trace_id", ckdb.String),
		ckdb.NewColumn("encoded_span_list", ckdb.String),
	}
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

func (t *TraceTree) Encode() {
	encoder := &codec.SimpleEncoder{}
	t.encodedSpans = t.encodedSpans[:0]
	encoder.Init(t.encodedSpans)
	encoder.WriteU8(TRACE_TREE_VERSION)
	encoder.WriteU16(uint16(len(t.SpanInfos)))
	for _, s := range t.SpanInfos {
		encoder.WriteU8(s.AutoServiceType0)
		encoder.WriteU8(s.AutoServiceType1)
		encoder.WriteVarintU32(s.AutoServiceID0)
		encoder.WriteVarintU32(s.AutoServiceID1)
		encoder.WriteString255(s.AppService0)
		encoder.WriteString255(s.AppService1)
		encoder.WriteString255(s.Topic)

		encoder.WriteBool(s.IsIPv4)
		if s.IsIPv4 {
			encoder.WriteU32(s.IP40)
			encoder.WriteU32(s.IP41)
		} else {
			encoder.WriteIPv6(s.IP60)
			encoder.WriteIPv6(s.IP61)
		}
		encoder.WriteU8(s.Level0)
		encoder.WriteU8(s.Level1)
		encoder.WriteVarintU64(s.ResponseDurationSum)
		encoder.WriteVarintU32(s.ResponseTotal)
		encoder.WriteVarintU32(s.ResponseStatusServerErrorCount)
	}
	t.encodedSpans = encoder.Bytes()
}

func (t *TraceTree) Decode(decoder *codec.SimpleDecoder) error {
	version := decoder.ReadU8()
	if version != TRACE_TREE_VERSION {
		return fmt.Errorf("trace tree data version is %d expect version is %d", version, TRACE_TREE_VERSION)
	}
	spanCount := int(decoder.ReadU16())
	if cap(t.SpanInfos) < spanCount {
		t.SpanInfos = make([]SpanInfo, spanCount)
	} else {
		t.SpanInfos = t.SpanInfos[:spanCount]
	}
	for i := 0; i < spanCount; i++ {
		s := &t.SpanInfos[i]
		s.AutoServiceType0 = decoder.ReadU8()
		s.AutoServiceType1 = decoder.ReadU8()
		s.AutoServiceID0 = decoder.ReadVarintU32()
		s.AutoServiceID1 = decoder.ReadVarintU32()
		s.AppService0 = decoder.ReadString255()
		s.AppService1 = decoder.ReadString255()
		s.Topic = decoder.ReadString255()

		s.IsIPv4 = decoder.ReadBool()
		if s.IsIPv4 {
			s.IP40 = decoder.ReadU32()
			s.IP41 = decoder.ReadU32()
		} else {
			s.IP60 = make([]byte, 16)
			s.IP61 = make([]byte, 16)
			decoder.ReadIPv6(s.IP60)
			decoder.ReadIPv6(s.IP61)
		}
		s.Level0 = decoder.ReadU8()
		s.Level1 = decoder.ReadU8()
		s.ResponseDurationSum = decoder.ReadVarintU64()
		s.ResponseTotal = decoder.ReadVarintU32()
		s.ResponseStatusServerErrorCount = decoder.ReadVarintU32()
	}
	if decoder.Failed() {
		return fmt.Errorf("trace tree decode failed, offset is %d, buf length is %d ", decoder.Offset(), len(decoder.Bytes()))
	}
	return nil
}
