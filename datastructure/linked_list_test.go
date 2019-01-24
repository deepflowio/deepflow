package datastructure

import (
	"testing"
)

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
