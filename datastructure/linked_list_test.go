package datastructure

import (
	"testing"
)

func TestRemoveFirst(t *testing.T) {
	list := LinkedList{}
	list.PushBack(1)
	list.PushBack(2)
	list.Remove(func(x interface{}) bool { return x.(int) == 1 })
	it := list.Iterator()
	if v := it.Value(); v != 2 {
		t.Error("Should be 2, actually", v)
	}
}

func TestRemoveLast(t *testing.T) {
	list := LinkedList{}
	list.PushBack(1)
	list.PushBack(2)
	list.Remove(func(x interface{}) bool { return x.(int) == 2 })
	it := list.Iterator()
	it.Next()
	if !it.Empty() {
		t.Error("Iterator should be empty")
	}
	if list.PopFront() != 1 {
		t.Error("Should be 1")
	}
}
