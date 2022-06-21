package timemap

import (
	"testing"
)

func TestLinkedListPush(t *testing.T) {
	r := newRing(_BLOCK_SIZE)
	hashLinkedList := hashLinkedList(_LINK_NIL)
	timeLinkedList := timeLinkedList(_LINK_NIL)
	nodes := make([]int, 5)
	for i := range nodes {
		n := r.pushBack(newTestEntry(0, i))
		nodes[i] = n.index
	}
	hashOrder := []int{1, 3, 4, 2, 0}
	for _, i := range hashOrder {
		hashLinkedList.pushFront(r, r.get(i))
	}
	if s := hashLinkedList.String(r, "entry"); s != "head -> 0 -> 2 -> 4 -> 3 -> 1 -> nil" {
		t.Errorf("hashLinkedList内容不正确，为%s", s)
	}
	timeOrder := []int{4, 0, 2, 1, 3}
	for _, i := range timeOrder {
		timeLinkedList.pushFront(r, r.get(i))
	}
	if s := timeLinkedList.String(r, "entry"); s != "head -> 3 -> 1 -> 2 -> 0 -> 4 -> nil" {
		t.Errorf("timeLinkedList内容不正确，为%s", s)
	}
}

func TestLinkedListRemove(t *testing.T) {
	r := newRing(_BLOCK_SIZE)
	hashLinkedList := hashLinkedList(_LINK_NIL)
	timeLinkedList := timeLinkedList(_LINK_NIL)
	nodes := make([]int, 5)
	for i := range nodes {
		n := r.pushBack(newTestEntry(0, i))
		nodes[i] = n.index
	}
	hashOrder := []int{1, 3, 4, 2, 0}
	for _, i := range hashOrder {
		hashLinkedList.pushFront(r, r.get(i))
	}
	if s := hashLinkedList.String(r, "entry"); s != "head -> 0 -> 2 -> 4 -> 3 -> 1 -> nil" {
		t.Errorf("hashLinkedList内容不正确，为%s", s)
	}
	timeOrder := []int{4, 0, 2, 1, 3}
	for _, i := range timeOrder {
		timeLinkedList.pushFront(r, r.get(i))
	}
	if s := timeLinkedList.String(r, "entry"); s != "head -> 3 -> 1 -> 2 -> 0 -> 4 -> nil" {
		t.Errorf("timeLinkedList内容不正确，为%s", s)
	}

	if r.swapFront(3) {
		n := r.get(3)
		firstN := r.getFront()
		hashLinkedList.fixLink(r, n, firstN.index)
		timeLinkedList.fixLink(r, n, firstN.index)
		hashLinkedList.fixLink(r, firstN, n.index)
		timeLinkedList.fixLink(r, firstN, n.index)
	}
	hashLinkedList.remove(r, r.getFront())
	timeLinkedList.remove(r, r.getFront())
	r.popFront()
	if s := hashLinkedList.String(r, "entry"); s != "head -> 0 -> 2 -> 4 -> 1 -> nil" {
		t.Errorf("hashLinkedList内容不正确，为%s", s)
	}
	if s := timeLinkedList.String(r, "entry"); s != "head -> 1 -> 2 -> 0 -> 4 -> nil" {
		t.Errorf("timeLinkedList内容不正确，为%s", s)
	}
}

func TestLinkedListFind(t *testing.T) {
	r := newRing(_BLOCK_SIZE)
	timestamp := uint32(1234567890)
	hashLinkedList := hashLinkedList(_LINK_NIL)
	timeLinkedList := timeLinkedList(_LINK_NIL)
	nodes := make([]int, 5)
	for i := range nodes {
		n := r.pushBack(newTestEntry(timestamp, i))
		nodes[i] = n.index
	}
	hashOrder := []int{1, 3, 4, 2, 0}
	for _, i := range hashOrder {
		hashLinkedList.pushFront(r, r.get(i))
	}
	timeOrder := []int{4, 0, 2, 1, 3}
	for _, i := range timeOrder {
		timeLinkedList.pushFront(r, r.get(i))
	}

	n1 := hashLinkedList.find(r, &node{entry: newTestEntry(timestamp, 2)})
	n2 := timeLinkedList.find(r, &node{entry: newTestEntry(timestamp, 2)})
	if n1 == nil || n2 == nil || n1 != n2 {
		t.Error(n1, n2)
		t.Error("find()实现不正确")
	}
	if n := hashLinkedList.find(r, &node{entry: newTestEntry(timestamp, 1024)}); n != nil {
		t.Error("find()实现不正确")
	}
	if n := timeLinkedList.find(r, &node{entry: newTestEntry(timestamp+1, 2)}); n != nil {
		t.Error("find()实现不正确")
	}
}
