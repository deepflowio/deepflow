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
