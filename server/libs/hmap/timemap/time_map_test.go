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
	"hash/fnv"
	"math/rand"
	"sort"
	"testing"
)

func TestTimeMapSingleSlot(t *testing.T) {
	m := New(0, 65536, 1024, 60, 1)
	m.AddOrMerge(newTestDocument(65, "alice", 3))
	m.AddOrMerge(newTestDocument(65, "bob", 4))
	m.AddOrMerge(newTestDocument(110, "alice", 7))
	m.AddOrMerge(newTestDocument(121, "alice", 7))
	expected := []Entry{newTestDocument(60, "alice", 10), newTestDocument(60, "bob", 4)}
	result := m.GetOutput()
	m.ClearOutput()
	sortEntries(expected)
	sortEntries(result)
	if !checkEq(result, expected) {
		t.Fatalf("结果预期为%v，实际为%v", expected, result)
	}

	m.AddOrMerge(newTestDocument(200, "catherine", 7))
	expected = []Entry{newTestDocument(120, "alice", 7)}
	result = m.GetOutput()
	m.ClearOutput()
	sortEntries(expected)
	sortEntries(result)
	if !checkEq(result, expected) {
		t.Fatalf("结果预期为%v，实际为%v", expected, result)
	}
}

func TestTimeMapTwoSlots(t *testing.T) {
	m := New(0, 65536, 1024, 60, 2)
	m.AddOrMerge(newTestDocument(65, "alice", 3))
	m.AddOrMerge(newTestDocument(65, "bob", 4))
	m.AddOrMerge(newTestDocument(110, "alice", 7))
	m.AddOrMerge(newTestDocument(121, "alice", 7))
	expected := []Entry{}
	result := m.GetOutput()
	m.ClearOutput()
	if !checkEq(result, expected) {
		t.Fatalf("结果预期为%v，实际为%v", expected, result)
	}

	m.AddOrMerge(newTestDocument(200, "catherine", 7))
	expected = []Entry{newTestDocument(60, "alice", 10), newTestDocument(60, "bob", 4)}
	result = m.GetOutput()
	m.ClearOutput()
	sortEntries(expected)
	sortEntries(result)
	if !checkEq(result, expected) {
		t.Fatalf("结果预期为%v，实际为%v", expected, result)
	}
}

func TestTimeMapRandom(t *testing.T) {
	seeds := []int64{42, 233, 1024}
	for _, s := range seeds {
		if err := randomTimeMapTester(s); err != nil {
			t.Errorf("测试%d: %s", s, err)
		}
	}
}

func randomTimeMapTester(seed int64) error {
	rand.Seed(seed)
	interval := uint32(60)
	timeSlots := rand.Intn(10) + 1
	testIntervals := (rand.Intn(3) + 2) * timeSlots
	keys := []string{
		"alice", "bob", "catherine", "david", "eleven", "fox", "george",
		"hilton", "ivy", "jade", "kevin", "lyn", "may", "ninja", "oliver",
		"peter", "qui-gon", "ruby", "steven", "tony", "ulysses", "vincent",
		"winston", "xavi", "young", "zack",
	}
	expected := []Entry{}
	expectedIndex := make(map[string]int)
	intervalStart := uint32(120)
	m := New(0, 65536, 16, interval, timeSlots)
	for i := 0; i < testIntervals; i++ {
		nEntries := rand.Intn(128)
		for j := 0; j < nEntries; j++ {
			timestamp := intervalStart + uint32(rand.Intn(int(interval)*timeSlots))
			key := keys[rand.Intn(len(keys))]
			value := uint64(rand.Intn(128))
			entry := newTestDocument(timestamp, key, value)
			m.AddOrMerge(entry)
			timestamp = timestamp / interval * interval
			expectedEntry := newTestDocument(timestamp, key, value)
			kim := fmt.Sprintf("%d-%s", timestamp, key)
			if id, in := expectedIndex[kim]; in {
				expected[id].Merge(expectedEntry)
			} else {
				expectedIndex[kim] = len(expected)
				expected = append(expected, expectedEntry)
			}
		}
		intervalStart += interval
	}
	m.AdvanceTime(intervalStart + uint32(timeSlots)*2*interval)
	result := m.GetOutput()
	sortEntries(expected)
	sortEntries(result)
	if !checkEq(expected, result) {
		return errors.New("结果不匹配")
	}
	return nil
}

func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].Timestamp() == es[j].Timestamp() {
			return es[i].(*TestDocument).key < es[j].(*TestDocument).key
		}
		return es[i].Timestamp() < es[j].Timestamp()
	})
}

func checkEq(a, b []Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		da := a[i].(*TestDocument)
		db := b[i].(*TestDocument)
		if da.timestamp != db.timestamp || da.key != db.key || da.value != db.value {
			return false
		}
	}
	return true
}

type TestDocument struct {
	timestamp uint32
	hash      uint64
	key       string
	value     uint64
}

func newTestDocument(timestamp uint32, key string, value uint64) Entry {
	return &TestDocument{
		timestamp: timestamp,
		key:       key,
		value:     value,
	}
}

func (d *TestDocument) Timestamp() uint32 {
	return d.timestamp
}

func (d *TestDocument) SetTimestamp(timestamp uint32) {
	d.timestamp = timestamp
}

func (d *TestDocument) Hash() uint64 {
	if d.hash == 0 {
		h := fnv.New64a()
		h.Write([]byte(d.key))
		d.hash = h.Sum64()
	}
	return d.hash
}

func (d *TestDocument) Eq(other Entry) bool {
	if o, ok := other.(*TestDocument); ok {
		return d.key == o.key
	}
	return false
}

func (d *TestDocument) Merge(other Entry) {
	if o, ok := other.(*TestDocument); ok {
		d.value += o.value
	}
}

func (e *TestDocument) Clone() Entry {
	newEntry := *e
	return &newEntry
}

func (d *TestDocument) Release() {
}

func (d *TestDocument) String() string {
	return fmt.Sprintf("ts=%d:hash=%x:key=%s:value=%d", d.timestamp, d.Hash(), d.key, d.value)
}
