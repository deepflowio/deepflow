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

package segmenttree

import (
	"encoding/binary"
	"net"
	"testing"
)

type IPv4Interval struct {
	net.IPNet

	ipInt  uint32
	ipMask uint32
}

func (i *IPv4Interval) Lower() (endpoint Endpoint, closed bool) {
	return int64(i.ipInt), true
}

func (i *IPv4Interval) Upper() (endpoint Endpoint, closed bool) {
	return int64(i.ipInt + (^i.ipMask + 1)), false
}

func cidrToInterval(cidr string) Interval {
	_, ipNet, _ := net.ParseCIDR(cidr)
	ipInt := binary.BigEndian.Uint32(ipNet.IP)
	ipMask := binary.BigEndian.Uint32(ipNet.Mask)
	return &IPv4Interval{*ipNet, ipInt, ipMask}
}

func interval(cidrs ...string) []Interval {
	entries := make([]Interval, len(cidrs))
	for i, cidr := range cidrs {
		entries[i] = cidrToInterval(cidr)
	}
	return entries
}

type IntValue struct {
	value uint64
}

func (v *IntValue) Id() uint64 {
	return v.value
}

func (e *Entry) v(value uint64) *Entry {
	e.Value = &IntValue{value}
	return e
}

func e(cidrs ...string) *Entry {
	return &Entry{interval(cidrs...), nil}
}

func checkResult(results []Value, expect ...int) bool {
	if len(results) != len(expect) {
		return false
	}
	for i, e := range expect {
		if int(results[i].Id()) != e {
			return false
		}
	}
	return true
}

func TestEmpty(t *testing.T) {
	tree, _ := New(1)

	var results []Value
	results = tree.Query(&IntInterval{1, 1})
	if !checkResult(results) {
		t.Errorf("Expected [] but actually %s", results)
	}
}

func TestIpSegmentTree(t *testing.T) {
	tree, _ := New(2,
		*e("10.30.1.0/24", "10.30.0.0/16").v(1),
		*e("10.30.0.0/16", "10.30.1.0/24").v(2),
	)

	var results []Value
	results = tree.Query(interval("10.30.1.0/24", "10.30.1.0/24")...)
	if !checkResult(results, 1, 2) {
		t.Errorf("Expected [1, 2] but actually %s", results)
	}

	results = tree.Query(interval("10.30.1.0/24", "10.30.0.0/24")...)
	if !checkResult(results, 1) {
		t.Errorf("Expected [1] but actually %s", results)
	}
}

func TestEndpoint(t *testing.T) {
	tree, _ := New(1, asIntEntry(1, 1, 2))

	var results []Value
	results = tree.Query(&IntInterval{1, 1})
	if !checkResult(results, 2) {
		t.Errorf("Expected [2] but actually %s", results)
	}
}

func TestDeduplication(t *testing.T) {
	tree, _ := New(1,
		*e("10.30.1.0/24").v(1),
		*e("10.30.0.0/16").v(1),
	)

	results := tree.Query(interval("10.30.1.0/24")...)
	if !checkResult(results, 1) {
		t.Errorf("Expected [1] but actually %s", results)
	}
}

type IntInterval struct {
	from, to int
}

func (i *IntInterval) Lower() (Endpoint, bool) {
	return int64(i.from), true
}

func (i *IntInterval) Upper() (Endpoint, bool) {
	return int64(i.to), true
}

func asIntEntry(from, to, value int) Entry {
	return Entry{[]Interval{&IntInterval{from, to}}, &IntValue{uint64(value)}}
}

func BenchmarkBuildSegmentTree(b *testing.B) {
	entries := [14]Entry{}
	for i := 0; i < 14; i++ {
		entries[i] = asIntEntry(i, 14-i, i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = New(1, entries[:]...)
	}
}

func BenchmarkQuerySegmentTree(b *testing.B) {
	entries := [14]Entry{}
	for i := 0; i < 14; i++ {
		entries[i] = asIntEntry(i, 14-i, i)
	}
	tree, _ := New(1, entries[:]...)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.Query(&IntInterval{i % 16, (i + 2) % 16})
	}
}
