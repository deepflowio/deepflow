package lru

import (
	"testing"
)

func TestU32Keys(t *testing.T) {
	capacity := 100
	lru := NewCache32(capacity)
	for i := 0; i < capacity; i++ {
		lru.Add(uint32(i), uint32(i))
	}
	keys := lru.Keys()
	for index, key := range keys {
		if key != uint32(index) {
			t.Errorf("key %d is not expected", key)
			return
		}

		index++
	}
}

func TestU32Values(t *testing.T) {
	capacity := 100
	lru := NewCache32(capacity)
	for i := 0; i < capacity; i++ {
		lru.Add(uint32(i), i)
	}
	values := lru.Values()
	for index, value := range values {
		if value != index {
			t.Errorf("value %d is not expected", value)
			return
		}
	}
}

func TestU32Clear(t *testing.T) {
	capacity := 100
	lru := NewCache32(capacity)
	for i := 0; i < capacity; i++ {
		lru.Add(uint32(i), i)
	}
	lru.Clear()
	if lru.lruList != nil || lru.cache != nil {
		t.Errorf("value %v is not expected", lru)
	}
}

func TestU32RemoveAndContain(t *testing.T) {
	capacity := 100
	lru := NewCache32(capacity)
	for i := 0; i < capacity; i++ {
		lru.Add(uint32(i), i)
	}
	lru.Remove(3)
	if lru.Len() != 99 {
		t.Errorf("lru remove is not expected, current lru len %d", lru.Len())
	}
	if lru.Contain(3) == true {
		t.Errorf("value %v is not expected", lru.Contain(3))
	}
}
