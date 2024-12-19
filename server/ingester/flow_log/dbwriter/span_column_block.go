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

package dbwriter

import (
	"github.com/deepflowio/deepflow/server/libs/ckdb"

	"github.com/ClickHouse/ch-go/proto"
)

type SpanWithTraceIDBlock struct {
	ColTime        proto.ColDateTime
	ColTraceId     proto.ColStr
	ColSearchIndex proto.ColUInt64
	ColEncodedSpan proto.ColStr
}

func (b *SpanWithTraceIDBlock) Reset() {
	b.ColTime.Reset()
	b.ColTraceId.Reset()
	b.ColSearchIndex.Reset()
	b.ColEncodedSpan.Reset()
}

func (b *SpanWithTraceIDBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_TIME, Data: &b.ColTime},
		proto.InputColumn{Name: ckdb.COLUMN_TRACE_ID, Data: &b.ColTraceId},
		proto.InputColumn{Name: ckdb.COLUMN_SEARCH_INDEX, Data: &b.ColSearchIndex},
		proto.InputColumn{Name: ckdb.COLUMN_ENCODED_SPAN, Data: &b.ColEncodedSpan},
	)
}

func (n *SpanWithTraceID) NewColumnBlock() ckdb.CKColumnBlock {
	return &SpanWithTraceIDBlock{}
}

func (n *SpanWithTraceID) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*SpanWithTraceIDBlock)
	ckdb.AppendColDateTime(&block.ColTime, n.Time)
	block.ColTraceId.Append(n.TraceId)
	block.ColSearchIndex.Append(n.TraceIdIndex)
	n.Encode()
	block.ColEncodedSpan.AppendBytes(n.EncodedSpan)
}
