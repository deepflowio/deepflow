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
	"github.com/ClickHouse/ch-go/proto"

	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type TraceTreeBlock struct {
	ColTime            proto.ColDateTime
	ColSearchIndex     proto.ColUInt64
	ColTraceId         proto.ColStr
	ColTraceId2        proto.ColStr
	ColEncodedSpanList proto.ColStr
}

func (b *TraceTreeBlock) Reset() {
	b.ColTime.Reset()
	b.ColSearchIndex.Reset()
	b.ColTraceId.Reset()
	b.ColTraceId2.Reset()
	b.ColEncodedSpanList.Reset()
}

func (b *TraceTreeBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_TIME, Data: &b.ColTime},
		proto.InputColumn{Name: ckdb.COLUMN_SEARCH_INDEX, Data: &b.ColSearchIndex},
		proto.InputColumn{Name: ckdb.COLUMN_TRACE_ID, Data: &b.ColTraceId},
		proto.InputColumn{Name: ckdb.COLUMN_TRACE_ID_2, Data: &b.ColTraceId2},
		proto.InputColumn{Name: ckdb.COLUMN_ENCODED_SPAN_LIST, Data: &b.ColEncodedSpanList},
	)
}

func (n *TraceTree) NewColumnBlock() ckdb.CKColumnBlock {
	return &TraceTreeBlock{}
}

func (n *TraceTree) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*TraceTreeBlock)
	n.Encode()
	ckdb.AppendColDateTime(&block.ColTime, n.Time)
	block.ColSearchIndex.Append(n.SearchIndex)
	block.ColTraceId.Append(n.TraceId)
	block.ColTraceId2.Append(n.TraceId2)
	block.ColEncodedSpanList.AppendBytes(n.encodedTreeNodes)
}
