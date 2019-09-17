package lru

import (
	"testing"

	oldlru "gitlab.x.lan/yunshan/droplet-libs/lru"
)

func TestU64LRU(t *testing.T) {
	capacity := 256
	lru := NewU64LRU(capacity, capacity)

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
}

func BenchmarkU64LRUAdd(b *testing.B) {
	capacity := 1 << 20
	lru := NewU64LRU(int(capacity), int(capacity))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), uint64(i))
	}
}

func BenchmarkU64LRURemove(b *testing.B) {
	capacity := b.N
	lru := NewU64LRU(int(capacity), int(capacity))
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Remove(uint64(i))
	}
}

func BenchmarkU64LRUGet(b *testing.B) {
	capacity := 1 << 20
	lru := NewU64LRU(int(capacity), int(capacity))
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Get(uint64(i), false)
	}
}

func BenchmarkU64LRUPeek(b *testing.B) {
	capacity := 1 << 20
	lru := NewU64LRU(int(capacity), int(capacity))
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Get(uint64(i), true)
	}
}

func BenchmarkOldLRUAdd(b *testing.B) {
	capacity := 1 << 20
	lru := oldlru.NewCache64(capacity)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Add(uint64(i), i)
	}
}

func BenchmarkOldLRURemove(b *testing.B) {
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

func BenchmarkOldLRUGet(b *testing.B) {
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

func BenchmarkOldLRUPeek(b *testing.B) {
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
