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

package stats

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	. "github.com/deepflowio/deepflow/server/libs/datastructure"
)

// ---- Test fixtures ----

// structCounter exercises the struct-reflection path in counterToFields.
type structCounter struct {
	Recv  uint64  `statsd:"recv"`
	Drop  uint32  `statsd:"drop"`
	Delay float64 `statsd:"delay"`
	Label string  `statsd:"label"`
	priv  int     // unexported: must be skipped by counterToFields
}

type mockCountable struct {
	closed  bool
	counter interface{}
}

func (m *mockCountable) GetCounter() interface{} { return m.counter }
func (m *mockCountable) Closed() bool            { return m.closed }

// freshSources replaces statSources with an empty list and sets a predictable
// processName for the duration of the test, restoring originals on cleanup.
func freshSources(tb testing.TB) {
	tb.Helper()
	old := statSources
	oldProcess := processName
	statSources = LinkedList{}
	processName = "testproc"
	tb.Cleanup(func() {
		statSources = old
		processName = oldProcess
	})
}

// resetSkip forces all registered sources to emit on the next collectPoints call.
func resetSkip() {
	lock.Lock()
	for it := statSources.Iterator(); !it.Empty(); it.Next() {
		it.Value().(*StatSource).skip = 0
	}
	lock.Unlock()
}

// ---- Unit tests: counterToFields ----

func TestCounterToFields_UintTypesConvertToInt64(t *testing.T) {
	items := []StatItem{
		{"u", uint(10)},
		{"u8", uint8(20)},
		{"u16", uint16(30)},
		{"u32", uint32(40)},
		{"u64", uint64(50)},
	}
	result := counterToFields(items)
	if len(result) != 1 {
		t.Fatalf("len(result) = %d, want 1", len(result))
	}
	fields := result[0]

	want := map[string]int64{"u": 10, "u8": 20, "u16": 30, "u32": 40, "u64": 50}
	for k, wantV := range want {
		got, ok := fields[k]
		if !ok {
			t.Errorf("fields[%q] missing", k)
			continue
		}
		v, ok := got.(int64)
		if !ok {
			t.Errorf("fields[%q] type = %T, want int64", k, got)
		} else if v != wantV {
			t.Errorf("fields[%q] = %d, want %d", k, v, wantV)
		}
	}
}

func TestCounterToFields_NonUintPassThrough(t *testing.T) {
	items := []StatItem{
		{"count", int64(42)},
		{"rate", float64(3.14)},
		{"label", "hello"},
	}
	fields := counterToFields(items)[0]

	if v := fields["count"].(int64); v != 42 {
		t.Errorf("count = %v, want 42", v)
	}
	if v := fields["rate"].(float64); v != 3.14 {
		t.Errorf("rate = %v, want 3.14", v)
	}
	if v := fields["label"].(string); v != "hello" {
		t.Errorf("label = %v, want hello", v)
	}
}

func TestCounterToFields_StructPath(t *testing.T) {
	c := &structCounter{Recv: 1000, Drop: 5, Delay: 2.5, Label: "worker"}
	result := counterToFields(c)

	if len(result) != 1 {
		t.Fatalf("len(result) = %d, want 1", len(result))
	}
	fields := result[0]
	if len(fields) != 4 {
		t.Errorf("len(fields) = %d, want 4", len(fields))
	}
	if fields["recv"].(int64) != 1000 {
		t.Errorf("recv = %v, want 1000", fields["recv"])
	}
	if fields["drop"].(int64) != 5 {
		t.Errorf("drop = %v, want 5", fields["drop"])
	}
	if fields["delay"].(float64) != 2.5 {
		t.Errorf("delay = %v, want 2.5", fields["delay"])
	}
	if fields["label"].(string) != "worker" {
		t.Errorf("label = %v, want worker", fields["label"])
	}
	if _, ok := fields["priv"]; ok {
		t.Error("unexported field 'priv' must not appear in fields")
	}
}

func TestCounterToFields_SliceOfStructs(t *testing.T) {
	counters := []structCounter{
		{Recv: 100, Drop: 1, Delay: 0.1, Label: "a"},
		{Recv: 200, Drop: 2, Delay: 0.2, Label: "b"},
		{Recv: 300, Drop: 3, Delay: 0.3, Label: "c"},
	}
	result := counterToFields(counters)

	if len(result) != 3 {
		t.Fatalf("len(result) = %d, want 3", len(result))
	}
	for i, want := range []struct {
		recv  int64
		drop  int64
		delay float64
		label string
	}{
		{100, 1, 0.1, "a"},
		{200, 2, 0.2, "b"},
		{300, 3, 0.3, "c"},
	} {
		fm := result[i]
		if fm["recv"].(int64) != want.recv {
			t.Errorf("[%d] recv = %v, want %v", i, fm["recv"], want.recv)
		}
		if fm["drop"].(int64) != want.drop {
			t.Errorf("[%d] drop = %v, want %v", i, fm["drop"], want.drop)
		}
		if fm["delay"].(float64) != want.delay {
			t.Errorf("[%d] delay = %v, want %v", i, fm["delay"], want.delay)
		}
		if fm["label"].(string) != want.label {
			t.Errorf("[%d] label = %v, want %v", i, fm["label"], want.label)
		}
	}
}

func TestCounterToFields_EmptySlice(t *testing.T) {
	result := counterToFields([]structCounter{})
	if result != nil {
		t.Errorf("empty slice should return nil, got %v", result)
	}
}

func TestCounterToFields_SliceOfPointerToStructs(t *testing.T) {
	counters := []*structCounter{
		{Recv: 100, Drop: 1, Delay: 0.1, Label: "a"},
		{Recv: 200, Drop: 2, Delay: 0.2, Label: "b"},
	}
	result := counterToFields(counters)

	if len(result) != 2 {
		t.Fatalf("len(result) = %d, want 2", len(result))
	}
	if result[0]["recv"].(int64) != 100 || result[0]["label"].(string) != "a" {
		t.Errorf("[0] unexpected fields: %v", result[0])
	}
	if result[1]["recv"].(int64) != 200 || result[1]["label"].(string) != "b" {
		t.Errorf("[1] unexpected fields: %v", result[1])
	}
}

func TestCounterToFields_SliceOfPointerToStructs_NilSkipped(t *testing.T) {
	counters := []*structCounter{
		{Recv: 100, Label: "a"},
		nil,
		{Recv: 300, Label: "c"},
	}
	result := counterToFields(counters)

	if len(result) != 2 {
		t.Fatalf("len(result) = %d, want 2 (nil element skipped)", len(result))
	}
	if result[0]["recv"].(int64) != 100 {
		t.Errorf("[0] recv = %v, want 100", result[0]["recv"])
	}
	if result[1]["recv"].(int64) != 300 {
		t.Errorf("[1] recv = %v, want 300", result[1]["recv"])
	}
}

func TestCounterToFields_SliceAllNilPointers(t *testing.T) {
	counters := []*structCounter{nil, nil}
	result := counterToFields(counters)
	if result != nil {
		t.Errorf("all-nil slice should return nil, got %v", result)
	}
}

func TestCounterToFields_StructUintFieldsConvertToInt64(t *testing.T) {
	c := &structCounter{Recv: 0xFFFFFFFF, Drop: 0xFFFF}
	fields := counterToFields(c)[0]

	v, ok := fields["recv"].(int64)
	if !ok {
		t.Fatalf("recv type = %T, want int64", fields["recv"])
	}
	if v != int64(0xFFFFFFFF) {
		t.Errorf("recv = %d, want %d", v, int64(0xFFFFFFFF))
	}
}

// ---- Unit tests: sortTagPairs ----

func TestSortTagPairs_Correctness(t *testing.T) {
	names := []string{"zone", "host", "app", "env"}
	values := []string{"us-east", "srv1", "deepflow", "prod"}

	sortTagPairs(names, values)

	wantN := []string{"app", "env", "host", "zone"}
	wantV := []string{"deepflow", "prod", "srv1", "us-east"}
	if !reflect.DeepEqual(names, wantN) {
		t.Errorf("names = %v, want %v", names, wantN)
	}
	if !reflect.DeepEqual(values, wantV) {
		t.Errorf("values = %v, want %v", values, wantV)
	}
}

func TestSortTagPairs_AlreadySorted(t *testing.T) {
	names := []string{"app", "host", "zone"}
	values := []string{"deepflow", "srv1", "us-east"}
	origN := append([]string{}, names...)
	origV := append([]string{}, values...)

	sortTagPairs(names, values)

	if !reflect.DeepEqual(names, origN) || !reflect.DeepEqual(values, origV) {
		t.Error("already-sorted pairs must remain unchanged")
	}
}

func TestSortTagPairs_EdgeCases(t *testing.T) {
	sortTagPairs(nil, nil)
	sortTagPairs([]string{}, []string{})

	names := []string{"x"}
	values := []string{"v"}
	sortTagPairs(names, values)
	if names[0] != "x" || values[0] != "v" {
		t.Error("single-element pair must be unchanged")
	}
}

func TestSortTagPairs_TwoElements(t *testing.T) {
	names := []string{"z", "a"}
	values := []string{"last", "first"}
	sortTagPairs(names, values)
	if names[0] != "a" || values[0] != "first" {
		t.Errorf("got (%q,%q), want (a,first)", names[0], values[0])
	}
	if names[1] != "z" || values[1] != "last" {
		t.Errorf("got (%q,%q), want (z,last)", names[1], values[1])
	}
}

// ---- Unit tests: registration and collection ----

func TestCollectPoints_Basic(t *testing.T) {
	freshSources(t)

	c := &mockCountable{
		counter: []StatItem{{"packets", int64(42)}, {"bytes", int64(1024)}},
	}
	RegisterCountable("module1", c, OptionStatTags{"region": "cn"})
	resetSkip()

	pts := collectPoints(time.Now())
	if len(pts) != 1 {
		t.Fatalf("len(pts) = %d, want 1", len(pts))
	}
	p := pts[0]
	if p.name != "testproc_module1" {
		t.Errorf("name = %q, want testproc_module1", p.name)
	}
	if p.fields[0]["packets"].(int64) != 42 {
		t.Errorf("packets = %v, want 42", p.fields[0]["packets"])
	}
	if p.fields[0]["bytes"].(int64) != 1024 {
		t.Errorf("bytes = %v, want 1024", p.fields[0]["bytes"])
	}
	if p.tags["region"] != "cn" {
		t.Errorf("region tag = %q, want cn", p.tags["region"])
	}
}

func TestCollectPoints_ClosedCountableIsRemoved(t *testing.T) {
	freshSources(t)

	c := &mockCountable{counter: []StatItem{{"x", int64(1)}}}
	RegisterCountable("closable", c)
	resetSkip()

	if pts := collectPoints(time.Now()); len(pts) != 1 {
		t.Fatalf("before close: got %d points, want 1", len(pts))
	}

	c.closed = true
	resetSkip()
	if pts := collectPoints(time.Now()); len(pts) != 0 {
		t.Fatalf("after close: got %d points, want 0", len(pts))
	}
}

func TestCollectPoints_IntervalSkipping(t *testing.T) {
	freshSources(t)

	c := &mockCountable{counter: []StatItem{{"x", int64(1)}}}
	RegisterCountable("skip_test", c, OptionInterval(2*TICK_CYCLE))
	resetSkip()

	// Cycle 1: skip-- → -1, collect; skip resets to 2
	if pts := collectPoints(time.Now()); len(pts) != 1 {
		t.Fatalf("cycle1: want 1 point, got %d", len(pts))
	}
	// Cycle 2: skip-- → 1, skip!
	if pts := collectPoints(time.Now()); len(pts) != 0 {
		t.Fatalf("cycle2: want 0 points (skipped), got %d", len(pts))
	}
	// Cycle 3: skip-- → 0, collect; skip resets to 2
	if pts := collectPoints(time.Now()); len(pts) != 1 {
		t.Fatalf("cycle3: want 1 point, got %d", len(pts))
	}
}

func TestRegisterCountable_DuplicateReplacesExisting(t *testing.T) {
	freshSources(t)

	c1 := &mockCountable{counter: []StatItem{{"v", int64(1)}}}
	c2 := &mockCountable{counter: []StatItem{{"v", int64(2)}}}

	RegisterCountable("dup", c1)
	RegisterCountable("dup", c2) // same module → replaces c1

	resetSkip()
	pts := collectPoints(time.Now())
	if len(pts) != 1 {
		t.Fatalf("len(pts) = %d, want 1 (duplicate must be removed)", len(pts))
	}
	if pts[0].fields[0]["v"].(int64) != 2 {
		t.Errorf("v = %v, want 2 (latest registration)", pts[0].fields[0]["v"])
	}
}

func TestCollectPoints_ModulePrefix(t *testing.T) {
	freshSources(t)

	c := &mockCountable{counter: []StatItem{{"x", int64(1)}}}
	RegisterCountableWithModulePrefix("ingester_", "flow", c)
	resetSkip()

	pts := collectPoints(time.Now())
	if len(pts) != 1 {
		t.Fatalf("len(pts) = %d, want 1", len(pts))
	}
	if pts[0].name != "testproc_ingester_flow" {
		t.Errorf("name = %q, want testproc_ingester_flow", pts[0].name)
	}
}

func TestCollectPoints_MultipleSources(t *testing.T) {
	freshSources(t)

	const n = 10
	for i := 0; i < n; i++ {
		c := &mockCountable{counter: []StatItem{{"v", int64(i)}}}
		RegisterCountable(fmt.Sprintf("mod%d", i), c)
	}
	resetSkip()

	pts := collectPoints(time.Now())
	if len(pts) != n {
		t.Errorf("len(pts) = %d, want %d", len(pts), n)
	}
}

func TestCollectPoints_HostTagAdded(t *testing.T) {
	freshSources(t)
	oldHostname := hostname
	hostname = "testhost"
	defer func() { hostname = oldHostname }()

	c := &mockCountable{counter: []StatItem{{"x", int64(1)}}}
	RegisterCountable("tagged", c)
	resetSkip()

	pts := collectPoints(time.Now())
	if len(pts) != 1 {
		t.Fatalf("len(pts) = %d, want 1", len(pts))
	}
	if pts[0].tags["host"] != "testhost" {
		t.Errorf("host tag = %q, want testhost", pts[0].tags["host"])
	}
}

// ---- Benchmarks ----
//
// "Old" functions reproduce the pre-optimization implementations verbatim
// so `go test -bench=. -benchmem` shows the improvement directly.

// counterToFieldsOld reproduces the original uint-conversion path that called
// reflect.ValueOf(item.Value).Uint() instead of using a typed switch.
// Accepts interface{} (same as production counterToFields) for a fair comparison.
func counterToFieldsOld(counter interface{}) []map[string]interface{} {
	fields := make(map[string]interface{})
	if items, ok := counter.([]StatItem); ok {
		for _, item := range items {
			switch item.Value.(type) {
			case uint, uint8, uint16, uint32, uint64:
				fields[item.Name] = int64(reflect.ValueOf(item.Value).Uint())
			default:
				fields[item.Name] = item.Value
			}
		}
	}
	return []map[string]interface{}{fields}
}

// sortTagsOld reproduces the original two-pass approach: one map iteration to
// collect keys only, sort.Slice on keys, then a second map lookup per value.
func sortTagsOld(tags map[string]string) ([]string, []string) {
	names := make([]string, 0, len(tags))
	for k := range tags {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	values := make([]string, len(names))
	for i, k := range names {
		values[i] = tags[k]
	}
	return names, values
}

// sortTagsNew reproduces the new single-pass approach with insertion sort on pairs.
func sortTagsNew(tags map[string]string) ([]string, []string) {
	names := make([]string, 0, len(tags))
	values := make([]string, 0, len(tags))
	for k, v := range tags {
		names = append(names, k)
		values = append(values, v)
	}
	sortTagPairs(names, values)
	return names, values
}

var benchItems = []StatItem{
	{"recv_packets", uint64(1000)},
	{"send_packets", uint64(500)},
	{"drop_packets", uint32(10)},
	{"recv_bytes", uint64(65536)},
	{"send_bytes", uint64(32768)},
	{"errors", uint16(0)},
	{"latency_us", int64(150)},
	{"cpu_percent", float64(1.5)},
}

var benchTags = map[string]string{
	"host":    "server-001",
	"region":  "cn-east",
	"app":     "deepflow-agent",
	"env":     "prod",
	"version": "6.5.0",
}

// BenchmarkCounterToFields_StatItems_New: typed switch, no reflection for uints.
func BenchmarkCounterToFields_StatItems_New(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = counterToFields(benchItems)
	}
}

// BenchmarkCounterToFields_StatItems_Old: reflect.ValueOf per uint field.
func BenchmarkCounterToFields_StatItems_Old(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = counterToFieldsOld(benchItems)
	}
}

// counterToFieldsStructOld reproduces the original struct-reflection path:
// re-parses tags and calls strings.Split on every invocation.
func counterToFieldsStructOld(counter interface{}) []map[string]interface{} {
	fields := make(map[string]interface{})
	val := reflect.Indirect(reflect.ValueOf(counter))
	for i := 0; i < val.Type().NumField(); i++ {
		if !val.Field(i).CanInterface() {
			continue
		}
		field := val.Type().Field(i)
		statsTag := field.Tag.Get("statsd")
		if statsTag == "" {
			continue
		}
		statsOpts := strings.Split(statsTag, ",")
		switch val.Field(i).Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			fields[statsOpts[0]] = int64(val.Field(i).Uint())
		default:
			fields[statsOpts[0]] = val.Field(i).Interface()
		}
	}
	return []map[string]interface{}{fields}
}

// BenchmarkCounterToFields_Struct_New: cached field descriptors — tag parsing done once.
func BenchmarkCounterToFields_Struct_New(b *testing.B) {
	c := &structCounter{Recv: 1000, Drop: 5, Delay: 2.5, Label: "worker"}
	_ = counterToFields(c) // warm cache
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = counterToFields(c)
	}
}

// BenchmarkCounterToFields_Struct_Old: re-parses struct tags on every call.
func BenchmarkCounterToFields_Struct_Old(b *testing.B) {
	c := &structCounter{Recv: 1000, Drop: 5, Delay: 2.5, Label: "worker"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = counterToFieldsStructOld(c)
	}
}

// BenchmarkCounterToFields_SliceOfStructs: []struct path, 10-element slice.
func BenchmarkCounterToFields_SliceOfStructs(b *testing.B) {
	counters := make([]structCounter, 10)
	for i := range counters {
		counters[i] = structCounter{Recv: uint64(i * 1000), Drop: uint32(i), Delay: float64(i) * 0.5, Label: "worker"}
	}
	_ = counterToFields(counters) // warm cache
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = counterToFields(counters)
	}
}

// BenchmarkSortTagPairs_New: single map pass + insertion sort on parallel name/value slices.
func BenchmarkSortTagPairs_New(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = sortTagsNew(benchTags)
	}
}

// BenchmarkSortTagPairs_Old: two map passes (keys, then values) + sort.Slice.
func BenchmarkSortTagPairs_Old(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = sortTagsOld(benchTags)
	}
}

// BenchmarkCollectPoints measures the full collection pipeline with 50 active sources.
// With default interval each call to collectPoints always emits (skip cycles through
// -1 → collect → 1 → 0 → collect, never blocking).
func BenchmarkCollectPoints(b *testing.B) {
	freshSources(b)
	for i := 0; i < 50; i++ {
		c := &mockCountable{counter: benchItems}
		RegisterCountable(fmt.Sprintf("module%d", i), c)
	}

	ts := time.Now()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = collectPoints(ts)
	}
}
