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
	"errors"
	"fmt"

	"github.com/deepflowio/deepflow/server/libs/hmap/keyhash"
)

const (
	INIT_OUTPUT_LEN = 1024
)

type TimeMap struct {
	id int

	entries  int
	capacity int

	hashSlots    int
	hashSlotBits int

	timeInterval       uint32
	timeSlots          int
	timeRingStartIndex int
	timeRingStartTime  uint32

	r *ring

	hashLists []hashLinkedList
	timeLists []timeLinkedList

	output []Entry
}

func minPowerOfTwo(v int) (int, int) {
	for i := 0; i < 30; i++ {
		if p := 1 << i; v <= p {
			return p, i
		}
	}
	return 1, 0
}

func New(id, capacity, hashSlots int, timeInterval uint32, timeSlots int) *TimeMap {
	hashSlots, hashSlotBits := minPowerOfTwo(hashSlots)
	if timeInterval == 0 {
		panic("timeInterval cannot be 0")
	}
	return &TimeMap{
		id:       id,
		capacity: capacity,

		hashSlots:    hashSlots,
		hashSlotBits: hashSlotBits,

		timeInterval: timeInterval,
		timeSlots:    timeSlots,

		r: newRing(capacity),

		hashLists: makeHashLinkedLists(hashSlots),
		timeLists: makeTimeLinkedLists(timeSlots),

		output: make([]Entry, 0, INIT_OUTPUT_LEN),
	}
}

func (m *TimeMap) AdvanceTime(timestamp uint32) {
	if timestamp < m.timeRingStartTime {
		return
	}
	advanceSlots := int((timestamp-m.timeRingStartTime)/m.timeInterval) - m.timeSlots + 1
	if advanceSlots <= 0 {
		return
	}
	if advanceSlots >= m.timeSlots {
		for i := range m.timeLists {
			// 从当前开始flush
			index := (i + m.timeRingStartIndex) % m.timeSlots
			m.flushTimeList(index)
		}
		m.timeRingStartIndex = 0
		m.timeRingStartTime = timestamp - uint32(m.timeSlots-1)*m.timeInterval
		return
	}
	for i := 0; i < advanceSlots; i++ {
		index := (i + m.timeRingStartIndex) % m.timeSlots
		m.flushTimeList(index)
	}
	m.timeRingStartIndex = (advanceSlots + m.timeRingStartIndex) % m.timeSlots
	m.timeRingStartTime += uint32(advanceSlots) * m.timeInterval
}

func (m *TimeMap) flushTimeList(index int) {
	nIndex := int(m.timeLists[index])
	for nIndex != _LINK_NIL {
		// 当前节点换到ring中第一个
		if m.r.swapFront(nIndex) {
			nodes := []*node{m.r.getFront(), m.r.get(nIndex)}
			for i, n := range nodes {
				m.hashLists[n.hashSlot].fixLink(m.r, n, nodes[1-i].index)
				m.timeLists[n.timeSlot].fixLink(m.r, n, nodes[1-i].index)
			}
		}
		n := m.r.getFront()
		m.output = append(m.output, n.entry)
		nIndex = n.timeLink.next
		m.hashLists[n.hashSlot].remove(m.r, n)
		m.timeLists[n.timeSlot].remove(m.r, n)
		m.r.popFront()
	}
	m.timeLists[index] = _LINK_NIL
}

// AddOrMerge does not consume entry
func (m *TimeMap) AddOrMerge(entry Entry) error {
	timestamp := entry.Timestamp()
	if timestamp < m.timeRingStartTime {
		return fmt.Errorf("entry too old, %d < %d", timestamp, m.timeRingStartTime)
	}
	timestamp = timestamp / m.timeInterval * m.timeInterval
	m.AdvanceTime(timestamp)

	entry.SetTimestamp(timestamp)
	entryHash := entry.Hash()
	slot := m.compressHash(keyhash.Jenkins128(uint64(timestamp), entryHash))
	if oldNode := m.hashLists[slot].find(m.r, &node{hash: entryHash, entry: entry}); oldNode != nil {
		oldNode.entry.Merge(entry)
		return nil
	}
	if m.entries >= m.capacity {
		return errors.New("too many entries")
	}
	newEntry := entry.Clone()
	node := m.r.pushBack(newEntry)
	node.hashSlot = slot
	m.hashLists[slot].pushFront(m.r, node)
	timeSlot := (int((timestamp-m.timeRingStartTime)/m.timeInterval) + m.timeRingStartIndex) % m.timeSlots
	node.timeSlot = timeSlot
	m.timeLists[timeSlot].pushFront(m.r, node)
	return nil
}

func (m *TimeMap) GetOutput() []Entry {
	return m.output
}

func (m *TimeMap) ClearOutput() {
	m.output = m.output[:0]
}

func (m *TimeMap) compressHash(hash int32) int {
	return int((hash>>m.hashSlotBits)^hash) & (m.hashSlots - 1)
}
