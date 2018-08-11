// Golang的list简直就是辣鸡
package utils

type Element struct {
	value interface{}
	next  *Element
}

type LinkedList struct {
	head *Element
	tail *Element
	size int
}

func (q *LinkedList) PushBack(v interface{}) {
	e := &Element{value: v}
	if q.size == 0 {
		q.head = e
	} else {
		q.tail.next = e
	}
	q.tail = e
	q.size++
}

func (q *LinkedList) PopFront() interface{} {
	if q.size == 0 {
		return nil
	}
	v := q.head.value
	q.head = q.head.next
	q.size--
	return v
}

func (q *LinkedList) Len() int {
	return q.size
}

func (q *LinkedList) Iterator() Iterator {
	return Iterator{q.head.next}
}

type Iterator struct {
	current *Element
}

func (it *Iterator) Next() {
	it.current = it.current.next
}

func (it *Iterator) Empty() bool {
	return it.current == nil
}

func (it *Iterator) Value() interface{} {
	return it.current.value
}
