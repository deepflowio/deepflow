package lru

import (
	"testing"
)

func TestKeys(t *testing.T) {
	capacity := 100
	lru := NewCache(capacity)
	for i := 0; i < capacity; i++ {
		lru.Add(i, i)
	}
	keys := lru.Keys()
	for index, key := range keys {
		if key != index {
			t.Errorf("key %d is not expected", key)
			return
		}
		index++
	}
}

func TestValues(t *testing.T) {
	capacity := 100
	lru := NewCache(capacity)
	for i := 0; i < capacity; i++ {
		lru.Add(i, i)
	}
	values := lru.Values()
	for index, value := range values {
		if value != index {
			t.Errorf("value %d is not expected", value)
			return
		}
	}
}

func TestClear(t *testing.T) {
	capacity := 100
	lru := NewCache(capacity)
	for i := 0; i < capacity; i++ {
		lru.Add(i, i)
	}
	lru.Clear()
	if lru.lruList != nil || lru.cache != nil {
		t.Errorf("value %v is not expected", lru)
	}
}

func TestRemoveAndContain(t *testing.T) {
	capacity := 100
	lru := NewCache(capacity)
	for i := 0; i < capacity; i++ {
		lru.Add(i, i)
	}
	lru.Remove(3)
	if lru.Len() != 99 {
		t.Errorf("lru remove is not expected, current lru len %d", lru.Len())
	}
	if lru.Contain(3) == true {
		t.Errorf("value %v is not expected", lru.Contain(3))
	}
}
