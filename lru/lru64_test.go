package lru

import (
	"testing"
)

func TestU64Keys(t *testing.T) {
	capacity := 100
	lru := NewCache64(capacity)
	for i := 0; i < capacity; i++ {
		lru.Add(uint64(i), uint64(i))
	}
	keys := lru.Keys()
	for index, key := range keys {
		if key != uint64(index) {
			t.Errorf("key %d is not expected", key)
			return
		}

		index++
	}
}

func TestU64Values(t *testing.T) {
	capacity := 100
	lru := NewCache64(capacity)
	for i := 0; i < capacity; i++ {
		lru.Add(uint64(i), i)
	}
	values := lru.Values()
	for index, value := range values {
		v := value.(int)
		if v != index {
			t.Errorf("value %d is not expected", v)
			return
		}
	}
}

func TestU64Clear(t *testing.T) {
	capacity := 100
	lru := NewCache64(capacity)
	for i := 0; i < capacity; i++ {
		lru.Add(uint64(i), i)
	}
	lru.Clear()
	if lru.lruList != nil || lru.cache != nil {
		t.Errorf("value %v is not expected", lru)
	}
}

func TestU64RemoveAndContain(t *testing.T) {
	capacity := 100
	lru := NewCache64(capacity)
	for i := 0; i < capacity; i++ {
		lru.Add(uint64(i), i)
	}
	lru.Remove(3)
	if lru.Len() != 99 {
		t.Errorf("lru remove is not expected, current lru len %d", lru.Len())
	}
	if lru.Contain(3) == true {
		t.Errorf("value %v is not expected", lru.Contain(3))
	}
}
