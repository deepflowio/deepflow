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

package datastructure

import (
	"testing"
)

func TestRemoveFirst(t *testing.T) {
	list := LinkedList{}
	list.PushBack(1)
	list.PushBack(2)
	list.Remove(func(x interface{}) bool { return x.(int) == 1 })
	if list.Len() != 1 {
		t.Error("Should be 1, actually", list.Len())
	}
	it := list.Iterator()
	if v := it.Value(); v != 2 {
		t.Error("Should be 2, actually", v)
	}

	list.PushFront(3)
	if list.Len() != 2 {
		t.Error("Should be 2, actually", list.Len())
	}
	it = list.Iterator()
	if v := it.Value(); v != 3 {
		t.Error("Should be 3, actually", v)
	}
	it.Next()
	if v := it.Value(); v != 2 {
		t.Error("Should be 2, actually", v)
	}
}

func TestRemoveLast(t *testing.T) {
	list := LinkedList{}
	list.PushBack(1)
	list.PushBack(2)
	list.Remove(func(x interface{}) bool { return x.(int) == 2 })
	if list.Len() != 1 {
		t.Error("Should be 1, actually", list.Len())
	}
	it := list.Iterator()
	it.Next()
	if !it.Empty() {
		t.Error("Iterator should be empty")
	}

	list.PushBack(3)
	if list.Len() != 2 {
		t.Error("Should be 2, actually", list.Len())
	}
	it = list.Iterator()
	if v := it.Value(); v != 1 {
		t.Error("Should be 1, actually", v)
	}
	it.Next()
	if v := it.Value(); v != 3 {
		t.Error("Should be 3, actually", v)
	}
}

func TestRemoveToEmpty(t *testing.T) {
	list := LinkedList{}
	list.PushBack(1)
	list.PushBack(2)
	list.PopFront()
	list.PopFront()

	list.PushFront(1)
	list.PopFront()
	list.PushFront(2)
	list.PopFront()

	list.PushFront(1)
	list.PushFront(2)
	list.PopFront()
	list.PushFront(3)
	list.PopFront()
	list.PopFront()
}
