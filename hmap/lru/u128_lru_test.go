package lru

import (
	"bytes"
	"testing"
)

func TestU128LRU(t *testing.T) {
	capacity := 256
	lru := NewU128LRU("test", capacity, capacity)

	// 添加0~255并Get
	for i := 0; i < capacity; i++ {
		lru.Add(uint64(i), uint64(i+100), uint64(i))
	}
	for i := 0; i < capacity; i++ {
		value, ok := lru.Get(uint64(i), uint64(i+100), true)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}
	for i := capacity - 1; i >= 0; i-- {
		value, ok := lru.Get(uint64(i), uint64(i+100), false)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}

	// 清空后添加0~511，会剩余256~511，之后Get
	for i := 0; i < capacity; i++ {
		lru.Remove(uint64(i), uint64(i+100))
	}
	capacity *= 2
	for i := 0; i < capacity; i++ {
		lru.Add(uint64(i), uint64(i+100), uint64(i))
	}
	for i := 0; i < capacity/2; i++ {
		value, ok := lru.Get(uint64(i), uint64(i+100), true)
		if ok {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}
	for i := capacity / 2; i < capacity; i++ {
		value, ok := lru.Get(uint64(i), uint64(i+100), true)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}
	for i := capacity - 1; i >= capacity/2; i-- {
		value, ok := lru.Get(uint64(i), uint64(i+100), false)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}
	for i := capacity/2 - 1; i >= 0; i-- {
		value, ok := lru.Get(uint64(i), uint64(i+100), false)
		if ok {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}

	// 通过Get确保不会被清出LRU
	key0, key1, expect := uint64(0xFFFF), uint64(0xFFFFFF), uint64(0xFFFF)
	lru.Add(key0, key1, expect)
	for i := 0; i < capacity/2; i++ {
		lru.Add(uint64(i), uint64(i+100), uint64(i))
		lru.Get(key0, key1, false)
	}
	value, ok := lru.Get(key0, key1, true)
	if !ok || value.(uint64) != expect {
		t.Errorf("key {%d,%d => %d, exist=%v} is not expected", key0, key1, expect, ok)
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
		lru.Add(uint64(i), uint64(i+100), uint64(i))
	}
	for i := 0; i < capacity; i++ {
		value, ok := lru.Get(uint64(i), uint64(i+100), true)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}
	for i := capacity - 1; i >= 0; i-- {
		value, ok := lru.Get(uint64(i), uint64(i+100), false)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}

	// 添加10个后walk
	for i := 0; i < 10; i++ {
		lru.Add(uint64(i), uint64(i+100), uint64(i))
	}
	count := 0
	callback := func(key0, key1 uint64, value interface{}) { count += 1 }
	lru.Walk(callback)
	if count != lru.Size() {
		t.Errorf("Walk count %d is not expected", count)
	}
}

func BenchmarkU128LRUAdd(b *testing.B) {
	capacity := 1 << 20
	lru := NewU128LRU("test", int(capacity), int(capacity))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), uint64(i*2+b.N), uint64(i))
	}
}

func BenchmarkU128LRURemove(b *testing.B) {
	capacity := b.N
	lru := NewU128LRU("test", int(capacity), int(capacity))
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), uint64(i*2+b.N), uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Remove(uint64(i), uint64(i*2+b.N))
	}
}

func BenchmarkU128LRUGet(b *testing.B) {
	capacity := 1 << 20
	lru := NewU128LRU("test", int(capacity), int(capacity))
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), uint64(i*2+b.N), uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Get(uint64(i), uint64(i*2+b.N), false)
	}
}

func BenchmarkU128LRUPeek(b *testing.B) {
	capacity := 1 << 20
	lru := NewU128LRU("test", int(capacity), int(capacity))
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), uint64(i*2+b.N), uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Get(uint64(i), uint64(i*2+b.N), true)
	}
}

func TestU128LRUCollisionChain(t *testing.T) {
	m := NewU128LRU("test", 2, 100).NoStats()
	m.SetCollisionChainDebugThreshold(5)

	for i := 0; i < 10; i++ {
		m.Add(0, uint64(i), 0)
	}
	expected := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	if !bytes.Equal(m.GetCollisionChain(), expected) {
		t.Error("冲突链获取不正确")
	}

	m.Clear()
	m.SetCollisionChainDebugThreshold(10)
	for i := 0; i < 10; i++ {
		m.Add(0, uint64(i), 0)
	}
	if len(m.GetCollisionChain()) > 0 {
		t.Error("冲突链获取不正确")
	}
}
