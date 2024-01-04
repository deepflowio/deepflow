/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Golang的list简直就是辣鸡
package datastructure

import (
	"github.com/deepflowio/deepflow/server/libs/pool"
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

func (q *LinkedList) Remove(filter func(interface{}) bool) {
	for e, prev := q.head, (*Element)(nil); e != nil; {
		if !filter(e.value) {
			prev, e = e, e.next
			continue
		}
		q.size--
		toRelease := e
		if e == q.head {
			q.head = e.next
		}
		if e == q.tail {
			q.tail = prev
		}
		if prev != nil {
			prev.next = e.next
		}
		e = e.next
		releaseElement(toRelease)
	}
}

func (q *LinkedList) Len() int {
	return q.size
}

func (q *LinkedList) Iterator() Iterator {
	return Iterator{q.head}
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
