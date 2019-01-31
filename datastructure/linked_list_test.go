package datastructure

import (
	"testing"
)

func TestRemoveFirst(t *testing.T) {
	list := LinkedList{}
	list.PushBack(1)
	list.PushBack(2)
	it := list.Iterator()
	t.Log(list.Remove(&it))
	if v := list.Remove(&it); v != 2 {
		t.Error("Should be 2, actually", v)
	}
}

func TestRemoveLast(t *testing.T) {
	list := LinkedList{}
	list.PushBack(1)
	list.PushBack(2)
	it := list.Iterator()
	it.Next()
	list.Remove(&it)
	if !it.Empty() {
		t.Error("Iterator should be empty")
	}
	if list.PopFront() != 1 {
		t.Error("Should be 1")
	}
}
