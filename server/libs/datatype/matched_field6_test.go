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
	"encoding/binary"
	"net"
	"reflect"
	"testing"
)

func newMatchedField6(tap TapType, proto uint8, srcIp, dstIp net.IP, srcPort, dstPort uint16) MatchedField6 {
	matched := MatchedField6{}
	matched.Set(MATCHED6_TAP_TYPE, uint64(tap))
	matched.Set(MATCHED6_PROTO, uint64(proto))
	srcIp0 := binary.BigEndian.Uint64(srcIp)
	srcIp1 := binary.BigEndian.Uint64(srcIp[8:])
	dstIp0 := binary.BigEndian.Uint64(dstIp)
	dstIp1 := binary.BigEndian.Uint64(dstIp[8:])
	matched.Set(MATCHED6_SRC_IP0, srcIp0)
	matched.Set(MATCHED6_SRC_IP1, srcIp1)
	matched.Set(MATCHED6_DST_IP0, dstIp0)
	matched.Set(MATCHED6_DST_IP1, dstIp1)
	matched.Set(MATCHED6_SRC_PORT, uint64(srcPort))
	matched.Set(MATCHED6_DST_PORT, uint64(dstPort))
	return matched
}

func TestMatchedField6SetGet1(t *testing.T) {
	matched := newMatchedField6(231, 3, net.ParseIP("aabb:ccdd::1"), net.ParseIP("1122:3344::2"), 50, 60)
	if matched.Get(MATCHED6_TAP_TYPE) != 231 {
		t.Errorf("MATCHED6_TAP_TYPE Error. %v\n", matched)
	}
	if matched.Get(MATCHED6_PROTO) != 3 {
		t.Errorf("MATCHED6_PROTO Error. %s\n", matched)
	}
	if matched.Get(MATCHED6_SRC_IP0) != 0xaabbccdd00000000 {
		t.Errorf("MATCHED6_SRC_IP0 Error. %s\n", matched)
	}
	if matched.Get(MATCHED6_SRC_PORT) != 50 {
		t.Errorf("MATCHED6_SRC_PORT Error. %s\n", matched)
	}
	if matched.Get(MATCHED6_DST_IP1) != 2 {
		t.Errorf("MATCHED6_DST_IP1 Error. %s\n", matched)
	}
	if matched.Get(MATCHED6_DST_PORT) != 60 {
		t.Errorf("MATCHED6_DST_PORT Error. %s\n", matched)
	}
}

func TestMatchedField6GetAllTableIndex(t *testing.T) {
	// 若matched为0101， vector为0111, mask为1001，返回{001,011,101,111}
	matched := newMatchedField6(1, 3, net.ParseIP("aabb:ccdd::1"), net.ParseIP("1122:3344::2"), 5, 60)
	vector := newMatchedField6(0, 0, net.ParseIP("::"), net.ParseIP("::"), 7, 0)
	mask := newMatchedField6(0, 0, net.ParseIP("::"), net.ParseIP("::"), 9, 0)
	indexs := matched.GetAllTableIndex(&vector, &mask, 288, 304, []int{288, 289, 290})
	if !reflect.DeepEqual([]uint16{1, 3, 5, 7}, indexs) {
		t.Errorf("TestMatchedField6GetAllTableIndex Error. %+v\n", indexs)
	}
}
