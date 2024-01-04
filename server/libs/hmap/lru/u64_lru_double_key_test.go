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

package lru

import (
	"bytes"
	"testing"

	"github.com/deepflowio/deepflow/server/libs/hmap"
)

const (
	_EVEN_NUMBER_KEY = uint64(100)
	_ODD_NUMBER_KEY  = uint64(101)
	_NOT_EXIST_KEY   = uint64(2048)
	_NUMBER_KEY      = (1)
	_SHORT_KEY_SORTS = 2
	_CAPACITY        = 10
)

func TestU64LRUAddAndRemove(t *testing.T) {
	lru := NewU64DoubleKeyLRU("test", _CAPACITY, _SHORT_KEY_SORTS, _CAPACITY)

	// 添加0~9
	for i := 0; i < _CAPACITY; i++ {
		if i%2 == 0 {
			lru.Add(uint64(i), _EVEN_NUMBER_KEY, uint64(i+10))
		} else {
			lru.Add(uint64(i), _ODD_NUMBER_KEY, uint64(i+10))
		}
	}
	_, ok := lru.Get(uint64(6), true)
	if !ok {
		t.Error("lru get is not expected, value of the key(uint64(6)) was not found")
	}

	// 删除第6个longKey的LRUNode
	lru.Remove(uint64(6))
	value, ok1 := lru.Get(uint64(6), true)
	if ok1 {
		t.Errorf("lru remove is not expected, value %v is not deleted", value)
	}
	expectValues := []uint64{18, 14, 12, 10}
	evenValues, _ := lru.PeekByShortKey(_EVEN_NUMBER_KEY)

	if evenValues[0] != expectValues[0] && evenValues[1] != expectValues[1] && evenValues[2] != expectValues[2] && evenValues[3] != expectValues[3] {
		t.Errorf("lru PeekByShortKey is not expected, values of the shortkey %v was not found", _ODD_NUMBER_KEY)
	}

	// 删除所有奇数
	lru.RemoveByShortKey(_ODD_NUMBER_KEY)
	evenValues, ok = lru.PeekByShortKey(_ODD_NUMBER_KEY)
	if ok {
		t.Errorf("lru RemoveByShortKey is not expected, actualValues %v is not deleted", evenValues)
	}

	// 删除所有偶数
	lru.RemoveByShortKey(_EVEN_NUMBER_KEY)
	evenValues, ok = lru.PeekByShortKey(_EVEN_NUMBER_KEY)
	if ok {
		t.Errorf("lru RemoveByShortKey is not expected, actualValues %v is not deleted", evenValues)
	}

	// 添加部分偶数
	values := []interface{}{18, 14, 12, 10}
	lru.AddByShortKey(expectValues, _EVEN_NUMBER_KEY, values)

	// 进行peek，查看新增是否成功
	evenValues, ok = lru.PeekByShortKey(_EVEN_NUMBER_KEY)
	if !ok {
		t.Errorf("lru PeekByShortKey is not expected, values of the shortkey %v was not found", _EVEN_NUMBER_KEY)
	}
}

func TestU64LRUAddAndRemoveByShortKey(t *testing.T) {
	evenNumbers := []uint64{0, 2, 4, 6, 8}
	oddNumbers := []uint64{1, 3, 5, 7, 9}
	evenValues := []interface{}{0, 2, 4, 6, 8}
	oddValues := []interface{}{1, 3, 5, 7, 9}

	lru := NewU64DoubleKeyLRU("test", _CAPACITY, _SHORT_KEY_SORTS, _CAPACITY)

	// 通过shortKey进行添加一组同类型数据
	lru.AddByShortKey(evenNumbers, _EVEN_NUMBER_KEY, evenValues)
	lru.AddByShortKey(oddNumbers, _ODD_NUMBER_KEY, oddValues)

	actualValues, ok := lru.PeekByShortKey(_ODD_NUMBER_KEY)

	if !ok {
		t.Errorf("lru PeekByShortKey is not expected, values of the shortkey %v was not found", _ODD_NUMBER_KEY)
	}

	// 删除奇数类型数据
	delCount := lru.RemoveByShortKey(_ODD_NUMBER_KEY)
	if delCount != len(oddValues) {
		t.Errorf("lru RemoveByShortKey is not expected, delCount is %v", delCount)
	}

	actualValues, ok = lru.PeekByShortKey(_ODD_NUMBER_KEY)
	if ok {
		t.Errorf("lru RemoveByShortKey is not expected, actualValues %v is not deleted", actualValues)
	}

	// 删除偶数类型数据
	lru.RemoveByShortKey(_EVEN_NUMBER_KEY)
	actualValues, ok = lru.PeekByShortKey(_EVEN_NUMBER_KEY)
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

func TestU64LRUAddAndRemoveByOneShortKey(t *testing.T) {
	lru := NewU64DoubleKeyLRU("test", _CAPACITY, _NUMBER_KEY, _CAPACITY)

	// 添加0~255
	for i := 0; i < _CAPACITY; i++ {
		lru.Add(uint64(i), _NUMBER_KEY, uint64(i))
	}

	_, ok := lru.Get(uint64(6), true)
	if !ok {
		t.Error("lru get is not expected, value of the key(uint64(6)) was not found")
	}
	lru.Remove(uint64(6))
	value, ok1 := lru.Get(uint64(6), true)
	if ok1 {
		t.Errorf("lru remove is not expected, value %v is not deleted", value)
	}

	// 删除该数据类型
	lru.RemoveByShortKey(_NUMBER_KEY)
	actualValues, ok2 := lru.PeekByShortKey(_NUMBER_KEY)
	if ok2 {
		t.Errorf("lru RemoveByShortKey is not expected, actualValues %v is not deleted", actualValues)
	}

	// 删除不存在类型
	lru.RemoveByShortKey(_NOT_EXIST_KEY)
	_, ok2 = lru.PeekByShortKey(_NOT_EXIST_KEY)
	if ok2 {
		t.Errorf("lru RemoveByShortKey is not expected, the shortkey %v is not exist", _NOT_EXIST_KEY)
	}

}

func TestU64DoubleKeyLRUCollisionChain(t *testing.T) {
	m := NewU64DoubleKeyLRU("test", _SHORT_KEY_SORTS, _SHORT_KEY_SORTS, _CAPACITY)
	m.SetCollisionChainDebugThreshold(5)

	// 添加0~9
	for i := 0; i < _CAPACITY; i++ {
		if i%2 == 0 {
			m.Add(uint64(i), _EVEN_NUMBER_KEY, uint64(i+10))
		} else {
			m.Add(uint64(i), _ODD_NUMBER_KEY, uint64(i+10))
		}
	}
	expected := []byte{
		0, 0, 0, 0, 0, 0, 0, 6,
		0, 0, 0, 0, 0, 0, 0, 5,
		0, 0, 0, 0, 0, 0, 0, 2,
		0, 0, 0, 0, 0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	if chain := m.GetCollisionChain(); !bytes.Equal(chain, expected) {
		t.Errorf("冲突链获取不正确, 应为%v, 实为%v", hmap.DumpHexBytesGrouped(expected, m.KeySize()), hmap.DumpHexBytesGrouped(chain, m.KeySize()))
	}

	m.SetCollisionChainDebugThreshold(10)
	if len(m.GetCollisionChain()) > 0 {
		t.Error("冲突链获取不正确")
	}

	m.SetCollisionChainDebugThreshold(5)
	expected = []byte{
		0, 0, 0, 0, 0, 0, 0, 100,
		0, 0, 0, 0, 0, 0, 0, 100,
		0, 0, 0, 0, 0, 0, 0, 100,
		0, 0, 0, 0, 0, 0, 0, 100,
		0, 0, 0, 0, 0, 0, 0, 100,
	}
	m.PeekByShortKey(_EVEN_NUMBER_KEY)
	if chain := m.GetCollisionChain(); !bytes.Equal(chain, expected) {
		t.Errorf("冲突链获取不正确, 应为%v, 实为%v", hmap.DumpHexBytesGrouped(expected, m.KeySize()), hmap.DumpHexBytesGrouped(chain, m.KeySize()))
	}

	m.Clear()
	m.Close()
}
