// Golang的list简直就是辣鸡
package datastructure

type LinkedList struct {
	head *Element
	tail *Element
	size int
}

func (q *LinkedList) PushFront(v interface{}) {
	e := WrapElement(v)
	if q.size == 0 {
		q.tail = e
	} else {
		e.Next = q.head
	}
	q.head = e
	q.size++
}

func (q *LinkedList) PushBack(v interface{}) {
	e := WrapElement(v)
	if q.size == 0 {
		q.head = e
	} else {
		q.tail.Next = e
	}
	q.tail = e
	q.size++
}

func (q *LinkedList) PopFront() interface{} {
	if q.size == 0 {
		return nil
	}
	element := q.head
	q.head = q.head.Next
	q.size--
	return UnwrapElement(element)
}

func (q *LinkedList) Remove(it *Iterator) interface{} {
	if it.head != q.head || it.current == nil {
		return nil
	}
	if q.head == it.current {
		it.Next()
		it.head = it.current
		return q.PopFront()
	}
	current := it.current
	it.prev.Next = current.Next
	if q.tail == current {
		q.tail = it.prev
	}
	q.size--
	it.Next()
	return UnwrapElement(current)
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
	it.prev, it.current = it.current, it.current.Next
}

func (it *Iterator) Empty() bool {
	return it.current == nil
}

func (it *Iterator) Value() interface{} {
	return it.current.Value
}
