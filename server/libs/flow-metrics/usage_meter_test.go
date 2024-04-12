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

package flow_metrics

import (
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"

	"testing"
)

func fillMetrics(hint uint64, m *UsageMeter) {
	m.PacketTx = hint * 3
	m.PacketRx = hint * 2
	m.ByteTx = hint * 97
	m.ByteRx = hint * 89
	m.L3ByteTx = hint * 96
	m.L3ByteRx = hint * 88
	m.L4ByteTx = hint * 95
	m.L4ByteRx = hint * 87
}

func TestVTAPMeterEnDecode(t *testing.T) {
	m := UsageMeter{}
	pbEncode := &pb.UsageMeter{}
	fillMetrics(1, &m)
	encoder := codec.SimpleEncoder{}
	m.WriteToPB(pbEncode)
	encoder.WritePB(pbEncode)

	decoder := codec.SimpleDecoder{}
	decoder.Init(encoder.Bytes())
	pbDecode := &pb.UsageMeter{}
	decoder.ReadPB(pbDecode)
	decoded := UsageMeter{}
	decoded.ReadFromPB(pbDecode)

	if m != decoded {
		t.Errorf("expect: %v, result %v", m, decoded)
	}
}

func TestVTAPMeterMerge(t *testing.T) {
	a := UsageMeter{}
	fillMetrics(1, &a)

	b := a
	fillMetrics(2, &b)
	b2 := b

	c := b
	fillMetrics(3, &c)

	b.ConcurrentMerge(&a)

	if b != c {
		t.Errorf("expect: %v, result %v", c, b)
	}

	b2.SequentialMerge(&a)

	if b2 != c {
		t.Errorf("expect: %v, result %v", c, b2)
	}
}
