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

package lru

import (
	"bytes"
	"testing"

	"github.com/deepflowio/deepflow/server/libs/hmap"
)

const (
	_FLOW_ID_TCP = uint64(1609901888847743149)
	_FLOW_ID_UDP = uint64(1609900789867547481)
)

func TestU128U64LRUAddAndRemove(t *testing.T) {
	lru := NewU128U64DoubleKeyLRU("test", _CAPACITY, _SHORT_KEY_SORTS, _CAPACITY)

	// 添加TCP流数据
	for i := 1; i <= _CAPACITY/2; i++ {
		lru.Add(_FLOW_ID_TCP, uint64(i), _FLOW_ID_TCP, uint64(i+10))
	}

	// 添加UDP流数据
	for i := 1; i <= _CAPACITY/2; i++ {
		lru.Add(_FLOW_ID_UDP, uint64(i), _FLOW_ID_UDP, uint64(i+100))
	}

	_, ok := lru.Get(_FLOW_ID_TCP, uint64(3), true)
	if !ok {
		t.Errorf("lru get is not expected, value of the longKey0[%v], longKey1[%v] was not found", _FLOW_ID_TCP, uint64(3))
	}

	// 删除第6个longKey的LRUNode
	lru.Remove(_FLOW_ID_TCP, uint64(3))
	value, ok1 := lru.Get(_FLOW_ID_TCP, uint64(3), true)
	if ok1 {
		t.Errorf("lru remove is not expected, value %v is not deleted", value)
	}
	expectValues := []uint64{15, 14, 12, 11}
	streamValues, _ := lru.PeekByShortKey(_FLOW_ID_TCP)

	if streamValues[0] != expectValues[0] && streamValues[1] != expectValues[1] && streamValues[2] != expectValues[2] && streamValues[3] != expectValues[3] {
		t.Errorf("lru PeekByShortKey is not expected, values of the shortkey %v was not found", _FLOW_ID_TCP)
	}

	// 删除指定TCP流
	lru.RemoveByShortKey(_FLOW_ID_TCP)
	streamValues, ok = lru.PeekByShortKey(_FLOW_ID_TCP)
	if ok {
		t.Errorf("lru RemoveByShortKey is not expected, actualValues %v is not deleted", streamValues)
	}

	// 删除指定UDP流
	lru.RemoveByShortKey(_FLOW_ID_UDP)
	streamValues, ok = lru.PeekByShortKey(_FLOW_ID_UDP)
	if ok {
		t.Errorf("lru RemoveByShortKey is not expected, actualValues %v is not deleted", streamValues)
	}

	// 添加一条UDP流
	values := []interface{}{15, 14, 12, 11}
	lru.AddByShortKey(expectValues, expectValues, _FLOW_ID_UDP, values)

	// 进行peek，查看新增是否成功
	streamValues, ok = lru.PeekByShortKey(_FLOW_ID_UDP)
	if !ok {
		t.Errorf("lru PeekByShortKey is not expected, values of the shortkey %v was not found", _FLOW_ID_UDP)
	}
}

func TestU128U64LRUAddAndRemoveByShortKey(t *testing.T) {
	tcpStreamIDs := []uint64{0, 2, 4, 6, 8}
	udpStreamIDs := []uint64{1, 3, 5, 7, 9}
	tcpValues := []interface{}{20, 40, 60, 80, 100}
	udpValues := []interface{}{10, 30, 50, 70, 90}

	lru := NewU128U64DoubleKeyLRU("test", _CAPACITY, _SHORT_KEY_SORTS, _CAPACITY)

	// 通过shortKey进行添加一组同类型数据
	lru.AddByShortKey(tcpStreamIDs, tcpStreamIDs, _FLOW_ID_TCP, tcpValues)
	lru.AddByShortKey(udpStreamIDs, udpStreamIDs, _FLOW_ID_UDP, udpValues)

	actualValues, ok := lru.PeekByShortKey(_FLOW_ID_TCP)
	if !ok {
		t.Errorf("lru PeekByShortKey is not expected, values of the shortkey %v was not found", _FLOW_ID_TCP)
	}

	// 删除指定TCP流数据
	delCount := lru.RemoveByShortKey(_FLOW_ID_TCP)
	if delCount != len(tcpValues) {
		t.Errorf("lru RemoveByShortKey is not expected, delCount is %v", delCount)
	}

	actualValues, ok = lru.PeekByShortKey(_FLOW_ID_TCP)
	if ok {
		t.Errorf("lru RemoveByShortKey is not expected, actualValues %v is not deleted", actualValues)
	}

	// 删除指定UDP流数据
	lru.RemoveByShortKey(_FLOW_ID_UDP)
	actualValues, ok = lru.PeekByShortKey(_FLOW_ID_UDP)
	if ok {
		t.Errorf("lru RemoveByShortKey is not expected, actualValues %v is not deleted", actualValues)
	}

	// 删除不存在类型
	lru.RemoveByShortKey(_NOT_EXIST_KEY)
	actualValues, ok = lru.PeekByShortKey(_NOT_EXIST_KEY)
	if ok {
		t.Errorf("lru RemoveByShortKey is not expected, actualValues %v is not exists", actualValues)
	}
}

func TestU128U64LRUCollisionChain(t *testing.T) {
	m := NewU128U64DoubleKeyLRU("test", _SHORT_KEY_SORTS, _SHORT_KEY_SORTS, _CAPACITY)
	m.SetCollisionChainDebugThreshold(5)
	for i := 0; i < _CAPACITY; i++ {
		if i%2 == 0 {
			m.Add(0, uint64(i), _FLOW_ID_TCP, uint64(i+10))
		} else {
			m.Add(0, uint64(i), _FLOW_ID_UDP, uint64(i+10))
		}
	}

	expected := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}

	if chain := m.GetCollisionChain(); !bytes.Equal(chain, expected) {
		t.Errorf("冲突链获取不正确, 应为%v, 实为%v", hmap.DumpHexBytesGrouped(expected, m.KeySize()), hmap.DumpHexBytesGrouped(chain, m.KeySize()))
	}

	m.SetCollisionChainDebugThreshold(10)
	expected = []byte{
		22, 87, 132, 61, 31, 173, 11, 89, 0, 0, 0, 0, 0, 0, 0, 0,
		22, 87, 133, 61, 0, 0, 8, 173, 0, 0, 0, 0, 0, 0, 0, 0,
		22, 87, 132, 61, 31, 173, 11, 89, 0, 0, 0, 0, 0, 0, 0, 0,
		22, 87, 133, 61, 0, 0, 8, 173, 0, 0, 0, 0, 0, 0, 0, 0,
		22, 87, 132, 61, 31, 173, 11, 89, 0, 0, 0, 0, 0, 0, 0, 0,
		22, 87, 133, 61, 0, 0, 8, 173, 0, 0, 0, 0, 0, 0, 0, 0,
		22, 87, 132, 61, 31, 173, 11, 89, 0, 0, 0, 0, 0, 0, 0, 0,
		22, 87, 133, 61, 0, 0, 8, 173, 0, 0, 0, 0, 0, 0, 0, 0,
		22, 87, 132, 61, 31, 173, 11, 89, 0, 0, 0, 0, 0, 0, 0, 0,
		22, 87, 133, 61, 0, 0, 8, 173, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	m.PeekByShortKey(_FLOW_ID_UDP)

	if chain := m.GetCollisionChain(); !bytes.Equal(chain, expected) {
		t.Errorf("冲突链获取不正确, 应为%v, 实为%v", hmap.DumpHexBytesGrouped(expected, m.KeySize()), hmap.DumpHexBytesGrouped(chain, m.KeySize()))
	}

	m.Clear()
	m.Close()
}
