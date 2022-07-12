/*
 * Copyright (c) 2022 Yunshan Networks
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

import "strings"

import "fmt"

type ring struct {
	blocks     []nodeBlock
	startIndex int
	endIndex   int

	maxIndex int
	capacity int
}

func newRing(capacity int) *ring {
	if capacity <= 0 {
		panic("invalid capacity")
	}
	nBlocks := (capacity + _BLOCK_SIZE - 1) / _BLOCK_SIZE
	return &ring{
		blocks:   make([]nodeBlock, nBlocks),
		maxIndex: nBlocks << _BLOCK_SIZE_BITS,
		capacity: capacity,
	}
}

func (r *ring) incIndex(index int) int {
	return (index + 1) % r.maxIndex
}

func (r *ring) decIndex(index int) int {
	return (index + r.maxIndex - 1) % r.maxIndex
}

func (r *ring) get(index int) *node {
	return &r.blocks[index>>_BLOCK_SIZE_BITS][index&_BLOCK_SIZE_MASK]
}

func (r *ring) getFront() *node {
	return r.get(r.startIndex)
}

func (r *ring) getNext() *node {
	index := r.endIndex
	r.endIndex = r.incIndex(r.endIndex)
	row := index >> _BLOCK_SIZE_BITS
	if r.blocks[row] == nil {
		r.blocks[row] = blockPool.Get().(nodeBlock)
	}
	entry := &r.blocks[row][index&_BLOCK_SIZE_MASK]
	entry.index = index
	return entry
}

func (r *ring) pushBack(entry Entry) *node {
	n := r.getNext()
	n.hash = entry.Hash()
	n.entry = entry
	return n
}

func (r *ring) popFront() {
	*r.get(r.startIndex) = node{}
	if r.startIndex&_BLOCK_SIZE_MASK == _BLOCK_SIZE_MASK {
		// put back empty block
		id := r.startIndex >> _BLOCK_SIZE_BITS
		blockPool.Put(r.blocks[id])
		r.blocks[id] = nil
	}
	r.startIndex = r.incIndex(r.startIndex)
}

// returns true if swapped
func (r *ring) swapFront(index int) bool {
	if index == r.startIndex {
		return false
	}

	n := r.get(index)
	firstN := r.get(r.startIndex)
	*n, *firstN = *firstN, *n
	n.index = index
	firstN.index = r.startIndex

	return true
}

// returns true if swapped
func (r *ring) swapRemove(index int) bool {
	swapped := r.swapFront(index)
	r.popFront()
	return swapped
}

func (r *ring) String() string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("[%d:%d]ring{", r.startIndex, r.endIndex))
	for i := r.startIndex; i != r.endIndex; i = r.incIndex(i) {
		if i != r.startIndex {
			sb.WriteString(", ")
		}
		sb.WriteString(r.get(i).String())
	}
	sb.WriteRune('}')
	return sb.String()
}
