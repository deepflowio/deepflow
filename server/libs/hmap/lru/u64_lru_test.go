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
	oldlru "github.com/deepflowio/deepflow/server/libs/lru"
)

func TestU64LRU(t *testing.T) {
	capacity := 256
	lru := NewU64LRU("test", capacity, capacity)

	// 添加0~255并Get
	for i := 0; i < capacity; i++ {
		lru.Add(uint64(i), uint64(i))
	}
	for i := 0; i < capacity; i++ {
		value, ok := lru.Get(uint64(i), true)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d => %d, exist=%v} is not expected", i, value, ok)
		}
	}
	for i := capacity - 1; i >= 0; i-- {
		value, ok := lru.Get(uint64(i), false)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d => %d, exist=%v} is not expected", i, value, ok)
		}
	}

	// 清空后添加0~511，会剩余256~511，之后Get
	for i := 0; i < capacity; i++ {
		lru.Remove(uint64(i))
	}
	capacity *= 2
	for i := 0; i < capacity; i++ {
		lru.Add(uint64(i), uint64(i))
	}
	for i := 0; i < capacity/2; i++ {
		value, ok := lru.Get(uint64(i), true)
		if ok {
			t.Errorf("key {%d => %d, exist=%v} is not expected", i, value, ok)
		}
	}
	for i := capacity / 2; i < capacity; i++ {
		value, ok := lru.Get(uint64(i), true)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d => %d, exist=%v} is not expected", i, value, ok)
		}
	}
	for i := capacity - 1; i >= capacity/2; i-- {
		value, ok := lru.Get(uint64(i), false)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d => %d, exist=%v} is not expected", i, value, ok)
		}
	}
	for i := capacity/2 - 1; i >= 0; i-- {
		value, ok := lru.Get(uint64(i), false)
		if ok {
			t.Errorf("key {%d => %d, exist=%v} is not expected", i, value, ok)
		}
	}

	// 通过Get确保不会被清出LRU
	key, expect := uint64(0xFFFF), uint64(0xFFFF)
	lru.Add(key, expect)
	for i := 0; i < capacity/2; i++ {
		lru.Add(uint64(i), uint64(i))
		lru.Get(0xFFFF, false)
	}
	value, ok := lru.Get(key, true)
	if !ok || value.(uint64) != expect {
		t.Errorf("key {%d => %d, exist=%v} is not expected", key, expect, ok)
	}

	// Size和Clear
	if lru.Size() != capacity/2 {
		t.Errorf("LRU已满，size %d，预期 %d", lru.Size(), capacity/2)
	}
	lru.Clear()
	if lru.Size() != 0 {
		t.Errorf("LRU清空后，size %d，预期 %d", lru.Size(), 0)
	}

	// 添加0~255并Get
	capacity /= 2
	for i := 0; i < capacity; i++ {
		lru.Add(uint64(i), uint64(i))
	}
	for i := 0; i < capacity; i++ {
		value, ok := lru.Get(uint64(i), true)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d => %d, exist=%v} is not expected", i, value, ok)
		}
	}
	for i := capacity - 1; i >= 0; i-- {
		value, ok := lru.Get(uint64(i), false)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d => %d, exist=%v} is not expected", i, value, ok)
		}
	}
}

func BenchmarkU64LRUAdd(b *testing.B) {
	capacity := 1 << 20
	lru := NewU64LRU("test", int(capacity), int(capacity))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), uint64(i))
	}

	lru.Close()
}

func BenchmarkU64LRURemove(b *testing.B) {
	capacity := b.N
	lru := NewU64LRU("test", int(capacity), int(capacity))
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Remove(uint64(i))
	}
	lru.Close()
}

func BenchmarkU64LRUGet(b *testing.B) {
	capacity := 1 << 20
	lru := NewU64LRU("test", int(capacity), int(capacity))
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Get(uint64(i), false)
	}
	lru.Close()
}

func BenchmarkU64LRUPeek(b *testing.B) {
	capacity := 1 << 20
	lru := NewU64LRU("test", int(capacity), int(capacity))
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Get(uint64(i), true)
	}
	lru.Close()
}

func BenchmarkOld64LRUAdd(b *testing.B) {
	capacity := 1 << 20
	lru := oldlru.NewCache64(capacity)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), i)
	}
}

func BenchmarkOld64LRURemove(b *testing.B) {
	capacity := b.N
	lru := oldlru.NewCache64(capacity)
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Remove(uint64(i))
	}
}

func BenchmarkOld64LRUGet(b *testing.B) {
	capacity := 1 << 20
	lru := oldlru.NewCache64(capacity)
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Get(uint64(i))
	}
}

func BenchmarkOld64LRUPeek(b *testing.B) {
	capacity := 1 << 20
	lru := oldlru.NewCache64(capacity)
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Peek(uint64(i))
	}
}

func BenchmarkOld32LRUAdd(b *testing.B) {
	capacity := 1 << 20
	lru := oldlru.NewCache32(capacity)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Add(uint32(i), i)
	}
}

func BenchmarkOld32LRURemove(b *testing.B) {
	capacity := b.N
	lru := oldlru.NewCache32(capacity)
	for i := 0; i < b.N; i++ {
		lru.Add(uint32(i), i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Remove(uint32(i))
	}
}

func BenchmarkOld32LRUGet(b *testing.B) {
	capacity := 1 << 20
	lru := oldlru.NewCache32(capacity)
	for i := 0; i < b.N; i++ {
		lru.Add(uint32(i), i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Get(uint32(i))
	}
}

func BenchmarkOld32LRUPeek(b *testing.B) {
	capacity := 1 << 20
	lru := oldlru.NewCache32(capacity)
	for i := 0; i < b.N; i++ {
		lru.Add(uint32(i), i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Peek(uint32(i))
	}
}

func TestU64LRUCollisionChain(t *testing.T) {
	m := NewU64LRU("test", 2, 100)
	m.SetCollisionChainDebugThreshold(5)

	for i := 0; i < 10; i++ {
		m.Add(uint64(i), 0)
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

	m.Clear()
	m.SetCollisionChainDebugThreshold(10)
	for i := 0; i < 10; i++ {
		m.Add(uint64(i), 0)
	}
	if len(m.GetCollisionChain()) > 0 {
		t.Error("冲突链获取不正确")
	}

	m.Close()
}
