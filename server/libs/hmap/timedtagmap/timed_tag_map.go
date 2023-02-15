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

package timedtagmap

import (
	"strconv"

	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

type TagID int32

const (
	INVALID_TAG_ID     = -1
	ALL_TAG_ID_INVALID = -1
	MIN_TTL            = 4  // 需要保证足够大的时间窗口，避免时间乱序时计算错误
	MAX_TTL            = 32 // 需要用32bit表示是否invalid
)

var tagIDSlicePool = pool.NewLockFreePool(func() interface{} {
	return make([]TagID, MAX_TTL+1)
})

func AcquireTagIDSlice(ttl int) []TagID {
	ti := tagIDSlicePool.Get().([]TagID)
	for i := 0; i < ttl; i++ {
		ti[i] = INVALID_TAG_ID
	}
	ti[ttl] = ALL_TAG_ID_INVALID // 最后一个ID的每个bit表示前面的ID是否invalid
	return ti
}

func ReleaseTagIDSlice(ti []TagID) {
	tagIDSlicePool.Put(ti)
}

type TagIDPair struct {
	tag string
	ids []TagID
}

type TimedTagMap struct {
	utils.Closable

	tagIDMap   map[string][]TagID
	tagIDPairs [][]TagIDPair

	oldestTime int
	ttl        int
	cap        int
	tagCount   int

	counter *TTMCounter
}

type TTMCounter struct {
	Hit      uint64 `statsd:"hit,count"`
	Miss     uint64 `statsd:"miss,count"`
	Expire   uint64 `statsd:"expire,count"`
	TagCount uint64 `statsd:"tag_count,gauge"`
	Cap      uint64 `statsd:"cap,gauge"`
}

func NewTimedTagMap(name string, thread int, ttl int) *TimedTagMap {
	// 强制将ttl置为[4, 32]之间的2^n，避免模运算
	t := MIN_TTL
	for t < ttl && t < MAX_TTL {
		t <<= 1
	}
	ttl = t

	m := &TimedTagMap{
		tagIDMap:   make(map[string][]TagID),
		tagIDPairs: make([][]TagIDPair, ttl),
		ttl:        ttl,
		counter:    &TTMCounter{},
	}

	for t = 0; t < ttl; t++ {
		m.tagIDPairs[t] = make([]TagIDPair, 0)
	}

	stats.RegisterCountable("ttm", m, []stats.Option{
		stats.OptionStatTags{"name": name},
		stats.OptionStatTags{"thread": strconv.Itoa(thread)},
	}...)

	return m
}

func (m *TimedTagMap) GetCounter() interface{} {
	var counter *TTMCounter
	counter, m.counter = m.counter, &TTMCounter{}

	counter.TagCount = uint64(m.tagCount)
	counter.Cap = uint64(m.cap)
	return counter
}

func (m *TimedTagMap) GetID(tag string, timestamp int) int {
	for ; timestamp-m.oldestTime >= m.ttl; m.oldestTime++ { // 清除过期的tag
		if m.oldestTime == 0 {
			m.oldestTime = timestamp - 1
		}

		t := m.oldestTime & (m.ttl - 1)
		if len(m.tagIDPairs[t]) == 0 {
			continue
		}

		for _, ti := range m.tagIDPairs[t] {
			ti.ids[t] = INVALID_TAG_ID
			ti.ids[m.ttl] |= 1 << uint8(t)
			if ti.ids[m.ttl] == ALL_TAG_ID_INVALID {
				delete(m.tagIDMap, ti.tag)
				ReleaseTagIDSlice(ti.ids)
				m.counter.Expire++
				m.tagCount--
			}
			ti.tag = ""
			ti.ids = nil
		}
		m.tagIDPairs[t] = m.tagIDPairs[t][:0]

		if len(m.tagIDMap)*8 < cap(m.tagIDPairs[t]) { // 缩减长度
			oldCap := cap(m.tagIDPairs[t])
			m.tagIDPairs[t] = make([]TagIDPair, 0, len(m.tagIDMap)*2)
			m.cap -= oldCap - cap(m.tagIDPairs[t])
		}
	}

	ts := timestamp & (m.ttl - 1)

	ids, ok := m.tagIDMap[tag]
	if !ok { // 新tag
		m.counter.Miss++
		m.tagCount++

		ids = AcquireTagIDSlice(m.ttl)
		ti := TagIDPair{tag: tag, ids: ids}
		for t := 0; t < m.ttl; t++ {
			ids[t] = INVALID_TAG_ID
		}
		ids[ts] = TagID(len(m.tagIDPairs[ts]))
		ids[m.ttl] = ^(1 << uint8(ts))

		oldCap := cap(m.tagIDPairs[ts])
		m.tagIDPairs[ts] = append(m.tagIDPairs[ts], ti)
		m.tagIDMap[tag] = ids

		m.cap += cap(m.tagIDPairs[ts]) - oldCap
		return int(ids[ts])
	}

	if ids[ts] == INVALID_TAG_ID { // tag存在，但当前时间没出现过
		ti := TagIDPair{tag: tag, ids: ids}
		ids[ts] = TagID(len(m.tagIDPairs[ts]))
		ids[m.ttl] &= ^(1 << uint8(ts))

		oldCap := cap(m.tagIDPairs[ts])
		m.tagIDPairs[ts] = append(m.tagIDPairs[ts], ti)

		m.cap += cap(m.tagIDPairs[ts]) - oldCap
		return int(ids[ts])
	}

	m.counter.Hit++
	return int(ids[ts])
}
