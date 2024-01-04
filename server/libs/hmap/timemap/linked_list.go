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

package timemap

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

const (
	_BLOCK_SIZE_BITS = 8
	_BLOCK_SIZE      = 1 << _BLOCK_SIZE_BITS
	_BLOCK_SIZE_MASK = _BLOCK_SIZE - 1
)

type node struct {
	hash uint64
	// 需要保证entry不为nil
	entry Entry

	// 在ring buffer中的index
	index int
	// hashmap的冲突链
	hashSlot int
	hashLink link
	// 时间链
	timeSlot int
	timeLink link
}

func (n *node) Hash() uint64 {
	if n.hash == 0 {
		// unlikely to happen after initialize
		n.hash = n.entry.Hash()
	}
	return n.hash
}

func (n *node) String() string {
	return fmt.Sprintf("timestamp=%d:entry=%v:id=%d:hashLink=%v:timeLink=%v", n.entry.Timestamp(), n.entry.String(), n.index, n.hashLink, n.timeLink)
}

func (n *node) ValueString(key string) string {
	switch key {
	case "timestamp":
		return strconv.FormatUint(uint64(n.entry.Timestamp()), 10)
	case "entry":
		return n.entry.String()
	case "index":
		return strconv.Itoa(n.index)
	case "hashLink":
		return fmt.Sprintf("%v", n.hashLink)
	case "timeLink":
		return fmt.Sprintf("%v", n.timeLink)
	default:
		return n.String()
	}
}

type nodeBlock []node

var blockPool = sync.Pool{
	New: func() interface{} {
		return nodeBlock(make([]node, _BLOCK_SIZE))
	},
}

const (
	_LINK_NIL = -1
)

type link struct {
	prev int
	next int
}

type linkedList int

type hashLinkedList linkedList
type timeLinkedList linkedList

func makeHashLinkedLists(n int) []hashLinkedList {
	if n == 0 {
		return nil
	}
	arr := make([]hashLinkedList, n)
	arr[0] = _LINK_NIL
	for seg := 1; seg < n; seg <<= 1 {
		copy(arr[seg:], arr[:seg])
	}
	return arr
}

func makeTimeLinkedLists(n int) []timeLinkedList {
	if n == 0 {
		return nil
	}
	arr := make([]timeLinkedList, n)
	arr[0] = _LINK_NIL
	for seg := 1; seg < n; seg <<= 1 {
		copy(arr[seg:], arr[:seg])
	}
	return arr
}

func (l *hashLinkedList) pushFront(r *ring, n *node) {
	lnk := &n.hashLink
	lnk.prev = _LINK_NIL
	lnk.next = int(*l)
	*l = hashLinkedList(n.index)
	if lnk.next != _LINK_NIL {
		r.get(lnk.next).hashLink.prev = n.index
	}
}

func (l *timeLinkedList) pushFront(r *ring, n *node) {
	lnk := &n.timeLink
	lnk.prev = _LINK_NIL
	lnk.next = int(*l)
	*l = timeLinkedList(n.index)
	if lnk.next != _LINK_NIL {
		r.get(lnk.next).timeLink.prev = n.index
	}
}

// 需要确保node在list中
func (l *hashLinkedList) remove(r *ring, n *node) {
	lnk := &n.hashLink
	if lnk.prev == _LINK_NIL {
		*l = hashLinkedList(lnk.next)
	} else {
		prevNode := r.get(lnk.prev)
		prevNode.hashLink.next = lnk.next
	}
	if lnk.next != _LINK_NIL {
		nextNode := r.get(lnk.next)
		nextNode.hashLink.prev = lnk.prev
	}
}

// 需要确保node在list中
func (l *timeLinkedList) remove(r *ring, n *node) {
	lnk := &n.timeLink
	if lnk.prev == _LINK_NIL {
		*l = timeLinkedList(lnk.next)
	} else {
		prevNode := r.get(lnk.prev)
		prevNode.timeLink.next = lnk.next
	}
	if lnk.next != _LINK_NIL {
		nextNode := r.get(lnk.next)
		nextNode.timeLink.prev = lnk.prev
	}
}

// 调用ring.swapFront返回true后需要调用
func (l *hashLinkedList) fixLink(r *ring, n *node, swappedIndex int) {
	lnk := &n.hashLink
	if lnk.prev == n.index {
		lnk.prev = swappedIndex
	}
	if lnk.next == n.index {
		lnk.next = swappedIndex
	}
	if lnk.prev != _LINK_NIL {
		r.get(lnk.prev).hashLink.next = n.index
	} else {
		*l = hashLinkedList(n.index)
	}
	if lnk.next != _LINK_NIL {
		r.get(lnk.next).hashLink.prev = n.index
	}
}

// 调用ring.swapFront返回true后需要调用
func (l *timeLinkedList) fixLink(r *ring, n *node, swappedIndex int) {
	lnk := &n.timeLink
	if lnk.prev == n.index {
		lnk.prev = swappedIndex
	}
	if lnk.next == n.index {
		lnk.next = swappedIndex
	}
	if lnk.prev != _LINK_NIL {
		r.get(lnk.prev).timeLink.next = n.index
	} else {
		*l = timeLinkedList(n.index)
	}
	if lnk.next != _LINK_NIL {
		r.get(lnk.next).timeLink.prev = n.index
	}
}

func (l *hashLinkedList) find(r *ring, n *node) *node {
	index := int(*l)
	for index != _LINK_NIL {
		queried := r.get(index)
		if queried.entry.Timestamp() == n.entry.Timestamp() && queried.Hash() == n.Hash() && queried.entry.Eq(n.entry) {
			return queried
		}
		index = queried.hashLink.next
	}
	return nil
}

func (l *timeLinkedList) find(r *ring, n *node) *node {
	index := int(*l)
	for index != _LINK_NIL {
		queried := r.get(index)
		if queried.entry.Timestamp() == n.entry.Timestamp() && queried.Hash() == n.Hash() && queried.entry.Eq(n.entry) {
			return queried
		}
		index = queried.timeLink.next
	}
	return nil
}

func (l *hashLinkedList) String(r *ring, key string) string {
	var nodes []string
	nodes = append(nodes, "head")
	index := int(*l)
	for index != _LINK_NIL {
		nodes = append(nodes, r.get(index).ValueString(key))
		index = r.get(index).hashLink.next
	}
	nodes = append(nodes, "nil")
	return strings.Join(nodes, " -> ")
}

func (l *timeLinkedList) String(r *ring, key string) string {
	var nodes []string
	nodes = append(nodes, "head")
	index := int(*l)
	for index != _LINK_NIL {
		nodes = append(nodes, r.get(index).ValueString(key))
		index = r.get(index).timeLink.next
	}
	nodes = append(nodes, "nil")
	return strings.Join(nodes, " -> ")
}
