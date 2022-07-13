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
	"reflect"
	"testing"
)

func newMatchedField(tap TapType, proto uint8, srcIp, dstIp uint32, srcPort, dstPort uint16) MatchedField {
	matched := MatchedField{}
	matched.Set(MATCHED_TAP_TYPE, uint64(tap))
	matched.Set(MATCHED_PROTO, uint64(proto))
	matched.Set(MATCHED_SRC_IP, uint64(srcIp))
	matched.Set(MATCHED_DST_IP, uint64(dstIp))
	matched.Set(MATCHED_SRC_PORT, uint64(srcPort))
	matched.Set(MATCHED_DST_PORT, uint64(dstPort))
	return matched
}

func TestSetGet1(t *testing.T) {
	matched := newMatchedField(66, 3, 20, 40, 50, 60)
	if matched.Get(MATCHED_TAP_TYPE) != 66 {
		t.Errorf("MATCHED_TAP_TYPE Error. %v\n", matched)
	}
	if matched.Get(MATCHED_PROTO) != 3 {
		t.Errorf("MATCHED_PROTO Error. %s\n", matched)
	}
	if matched.Get(MATCHED_SRC_IP) != 20 {
		t.Errorf("MATCHED_SRC_IP Error. %s\n", matched)
	}
	if matched.Get(MATCHED_SRC_PORT) != 50 {
		t.Errorf("MATCHED_SRC_PORT Error. %s\n", matched)
	}
	if matched.Get(MATCHED_DST_IP) != 40 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
	if matched.Get(MATCHED_DST_PORT) != 60 {
		t.Errorf("MATCHED_SRC_GROUP Error. %s\n", matched)
	}
}

func TestSetGet2(t *testing.T) {
	matched := newMatchedField(0xff, 0x7, 20, 40, 50, 60)
	if matched.Get(MATCHED_TAP_TYPE) != 0xff {
		t.Errorf("MATCHED_TAP_TYPE Error. %v\n", matched)
	}
	if matched.Get(MATCHED_PROTO) != 0x7 {
		t.Errorf("MATCHED_PROTO Error. %s\n", matched)
	}
}

func TestBitZero(t *testing.T) {
	matched := newMatchedField(1, 0, 1, 1, 1, 0)
	if matched.IsBitZero(0) != false {
		t.Errorf("0 bits Error. %s\n", matched)
	}
	if matched.IsBitZero(128) != true {
		t.Errorf("1 bits Error. %s\n", matched)
	}
}

func TestTableIndex(t *testing.T) {
	matched := newMatchedField(1, 1, 1, 1, 0, 0)
	maskVector := newMatchedField(1, 1, 0, 0, 0, 0)
	index := matched.GetTableIndex(&maskVector, 128, 144)
	if index != 0x3 {
		t.Errorf("TestTableIndex Error. %s\n", matched)
		t.Error("Expect index: 0x3.")
		t.Errorf("Actual index: %d.\n", index)
	}

	matched = newMatchedField(1, 1, 1, 1, 0, 0)
	maskVector = newMatchedField(1, 1, 0, 0, 0, 0)
	index = matched.GetTableIndex(&maskVector, 128, 144)
	if index != 0x3 {
		t.Errorf("TestTableIndex Error. %s\n", matched)
		t.Error("Expect index: 0x3.")
		t.Errorf("Actual index: %d.\n", index)
	}

	matched = newMatchedField(1, 1, 1, 1, 1, 1)
	maskVector = newMatchedField(0, 0, 0, 1, 1, 1)
	index = matched.GetTableIndex(&maskVector, 0, 144)
	if index != 0x7 {
		t.Errorf("TestTableIndex Error. %s\n", matched)
		t.Error("Expect index: 0x7.")
		t.Errorf("Actual index: %d.\n", index)
	}
}

func TestMatchedFieldGetAllTableIndex(t *testing.T) {
	// 若matched为0101， vector为0111, mask为1001，返回{001,011,101,111}
	matched := newMatchedField(1, 3, 20, 40, 5, 60)
	vector := newMatchedField(0, 0, 0, 0, 7, 0)
	mask := newMatchedField(0, 0, 0, 0, 9, 0)
	indexs := matched.GetAllTableIndex(&vector, &mask, 96, 114, []int{96, 97, 98})
	if !reflect.DeepEqual([]uint16{1, 3, 5, 7}, indexs) {
		t.Errorf("TestMatchedFieldGetAllTableIndex Error. %+v\n", indexs)
	}
}
