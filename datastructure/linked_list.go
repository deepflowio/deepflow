// Golang的list简直就是辣鸡
package datastructure

import (
	"gitlab.x.lan/yunshan/droplet-libs/pool"
)

var elementPool = pool.NewLockFreePool(func() interface{} {
	return new(Element)
})

type Element struct {
	value interface{}
	next  *Element
}

type LinkedList struct {
	head *Element
	tail *Element
	size int
}

func element(v interface{}) *Element {
	e := elementPool.Get().(*Element)
	e.value = v
	return e
}

func releaseElement(e *Element) {
	*e = Element{}
	elementPool.Put(e)
}

func (q *LinkedList) PushFront(v interface{}) {
	e := element(v)
	if q.size == 0 {
		q.tail = e
	} else {
		e.next = q.head
	}
	q.head = e
	q.size++
}

func (q *LinkedList) PushBack(v interface{}) {
	e := element(v)
	if q.size == 0 {
		q.head = e
	} else {
		q.tail.next = e
	}
	q.tail = e
	q.size++
}

func (q *LinkedList) PopFront() interface{} {
	var toRelease *Element
	if q.size == 0 {
		return nil
	}
	v := q.head.value
	toRelease, q.head = q.head, q.head.next
	releaseElement(toRelease)
	q.size--
	return v
}

func (q *LinkedList) Remove(it *Iterator) interface{} {
	if it.head != q.head {
		return nil
	}
	if q.head == it.current {
		return q.PopFront()
	}
	current := it.current
	it.prev.next = current.next
	v := current.value
	if q.tail == current {
		q.tail = it.prev
	}
	q.size--
	it.Next()
	releaseElement(current)
	return v
}

func (q *LinkedList) Len() int {
	return q.size
}

func (q *LinkedList) Iterator() Iterator {
	return Iterator{q.head, q.head, nil}
}

type Iterator struct {
	head    *Element
	current *Element
	prev    *Element
}

func (it *Iterator) Next() {
	it.prev, it.current = it.current, it.current.next
}

func (it *Iterator) Empty() bool {
	return it.current == nil
}

func (it *Iterator) Value() interface{} {
	return it.current.value
}
