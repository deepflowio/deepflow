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

import "strconv"

type TestEntry struct {
	timestamp uint32
	k         uint64
	v         uint64
}

func newTestEntry(t uint32, v int) Entry {
	e := TestEntry{
		timestamp: t,
		k:         uint64(v),
		v:         uint64(v),
	}
	return &e
}

func (e *TestEntry) Timestamp() uint32 {
	return e.timestamp
}

func (e *TestEntry) SetTimestamp(timestamp uint32) {
	e.timestamp = timestamp
}

func (e *TestEntry) Hash() uint64 {
	return e.k
}

func (e *TestEntry) Eq(other Entry) bool {
	return e.Hash() == other.Hash()
}

func (e *TestEntry) Merge(other Entry) {
	if o, ok := other.(*TestEntry); ok {
		e.v += o.v
	}
}

func (e *TestEntry) Clone() Entry {
	newEntry := *e
	return &newEntry
}

func (e *TestEntry) Release() {
}

func (e *TestEntry) String() string {
	return strconv.FormatUint(e.v, 10)
}
