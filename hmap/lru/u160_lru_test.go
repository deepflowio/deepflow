package lru

import (
	. "encoding/binary"
	"testing"
)

func getU160(a, b uint64) []byte {
	u := [20]byte{}
	BigEndian.PutUint64(u[:], a)
	BigEndian.PutUint64(u[8:], b)
	return u[:]
}

func TestU160LRU(t *testing.T) {
	capacity := 256
	lru := NewU160LRU(capacity, capacity)

	// 添加0~255并Get
	for i := 0; i < capacity; i++ {
		lru.Add(getU160(uint64(i), uint64(i+100)), uint64(i))
	}
	for i := 0; i < capacity; i++ {
		value, ok := lru.Get(getU160(uint64(i), uint64(i+100)), true)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}
	for i := capacity - 1; i >= 0; i-- {
		value, ok := lru.Get(getU160(uint64(i), uint64(i+100)), false)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}

	// 清空后添加0~511，会剩余256~511，之后Get
	for i := 0; i < capacity; i++ {
		lru.Remove(getU160(uint64(i), uint64(i+100)))
	}
	capacity *= 2
	for i := 0; i < capacity; i++ {
		lru.Add(getU160(uint64(i), uint64(i+100)), uint64(i))
	}
	for i := 0; i < capacity/2; i++ {
		value, ok := lru.Get(getU160(uint64(i), uint64(i+100)), true)
		if ok {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}
	for i := capacity / 2; i < capacity; i++ {
		value, ok := lru.Get(getU160(uint64(i), uint64(i+100)), true)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}
	for i := capacity - 1; i >= capacity/2; i-- {
		value, ok := lru.Get(getU160(uint64(i), uint64(i+100)), false)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}
	for i := capacity/2 - 1; i >= 0; i-- {
		value, ok := lru.Get(getU160(uint64(i), uint64(i+100)), false)
		if ok {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}

	// 通过Get确保不会被清出LRU
	key0, key1, expect := uint64(0xFFFF), uint64(0xFFFFFF), uint64(0xFFFF)
	lru.Add(getU160(key0, key1), expect)
	for i := 0; i < capacity/2; i++ {
		lru.Add(getU160(uint64(i), uint64(i+100)), uint64(i))
		lru.Get(getU160(key0, key1), false)
	}
	value, ok := lru.Get(getU160(key0, key1), true)
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
		lru.Add(getU160(uint64(i), uint64(i+100)), uint64(i))
	}
	for i := 0; i < capacity; i++ {
		value, ok := lru.Get(getU160(uint64(i), uint64(i+100)), true)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}
	for i := capacity - 1; i >= 0; i-- {
		value, ok := lru.Get(getU160(uint64(i), uint64(i+100)), false)
		if !ok || value.(uint64) != uint64(i) {
			t.Errorf("key {%d,%d => %d, exist=%v} is not expected", i, i+100, value, ok)
		}
	}
}

func BenchmarkU160LRUAdd(b *testing.B) {
	capacity := 1 << 20
	lru := NewU160LRU(int(capacity), int(capacity))
	keys := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = getU160(uint64(i), uint64(i*2+b.N))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Add(keys[i], uint64(i))
	}
}

func BenchmarkU160LRURemove(b *testing.B) {
	capacity := b.N
	lru := NewU160LRU(int(capacity), int(capacity))
	keys := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = getU160(uint64(i), uint64(i*2+b.N))
	}
	for i := 0; i < b.N; i++ {
		lru.Add(keys[i], uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Remove(keys[i])
	}
}

func BenchmarkU160LRUGet(b *testing.B) {
	capacity := 1 << 20
	lru := NewU160LRU(int(capacity), int(capacity))
	keys := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = getU160(uint64(i), uint64(i*2+b.N))
	}
	for i := 0; i < b.N; i++ {
		lru.Add(keys[i], uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Get(keys[i], false)
	}
}

func BenchmarkU160LRUPeek(b *testing.B) {
	capacity := 1 << 20
	lru := NewU160LRU(int(capacity), int(capacity))
	keys := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = getU160(uint64(i), uint64(i*2+b.N))
	}
	for i := 0; i < b.N; i++ {
		lru.Add(keys[i], uint64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lru.Get(keys[i], true)
	}
}
