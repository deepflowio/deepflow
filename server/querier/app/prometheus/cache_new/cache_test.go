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

package cachenew

import (
	"context"
	"sync"
	"testing"
	"time"

	cfg "github.com/deepflowio/deepflow/server/querier/app/prometheus/config"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/prompb"
)

func TestMain(m *testing.M) {
	config.Cfg = &config.QuerierConfig{Prometheus: cfg.Prometheus{Cache: cfg.PrometheusCache{
		RemoteReadCache:    true,
		CacheItemSize:      512 * 1024 * 1024,
		CacheMaxCount:      128,
		CacheFirstTimeout:  5,
		CacheCleanInterval: 3600,
		CacheAllowTimeGap:  1,
	}}}
	m.Run()
}

// ---------------------------------------------------------------------------
// TimedCache[int] — generic foundation tests
// ---------------------------------------------------------------------------

func newIntCache(maxCount int, allowGap int64) *TimedCache[int] {
	return NewTimedCache(Options[int]{
		MaxCount:      maxCount,
		MaxItemSize:   ^uint64(0),
		CleanInterval: time.Hour,
		AllowTimeGap:  allowGap,
		MergeFn:       func(cached int, _, _ int64, newData int, _, _ int64) int { return cached + newData },
		CopyFn:        func(v int) int { return v },
		SizeFn:        func(int) uint64 { return 8 },
	})
}

func TestTimedCache_Missing(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	l := c.Get("k1", 100, 200)
	if l.Status != StatusMissing {
		t.Fatalf("want StatusMissing, got %v", l.Status)
	}
	if l.QStart != 100 || l.QEnd != 200 {
		t.Fatalf("want [100,200], got [%d,%d]", l.QStart, l.QEnd)
	}
	c.Fail("k1")
}

func TestTimedCache_CompleteAndFullHit(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	// first get inserts placeholder
	l := c.Get("k1", 100, 200)
	if l.Status != StatusMissing {
		t.Fatalf("want StatusMissing, got %v", l.Status)
	}

	stored := c.Complete("k1", 100, 200, 42)
	if stored != 42 {
		t.Fatalf("want stored=42, got %d", stored)
	}

	l2 := c.Get("k1", 110, 190)
	if l2.Status != StatusFull {
		t.Fatalf("want StatusFull, got %v", l2.Status)
	}
	if l2.Data != 42 {
		t.Fatalf("want data=42, got %d", l2.Data)
	}
}

func TestTimedCache_PartialHit_Right(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	c.Complete("k1", 100, 200, 10)

	l := c.Get("k1", 150, 300)
	if l.Status != StatusPartial {
		t.Fatalf("want StatusPartial, got %v", l.Status)
	}
	if l.QStart != 200 || l.QEnd != 300 {
		t.Fatalf("want uncovered=[200,300], got [%d,%d]", l.QStart, l.QEnd)
	}
}

func TestTimedCache_PartialHit_Left(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	c.Complete("k1", 100, 200, 10)

	l := c.Get("k1", 50, 150)
	if l.Status != StatusPartial {
		t.Fatalf("want StatusPartial, got %v", l.Status)
	}
	if l.QStart != 50 || l.QEnd != 100 {
		t.Fatalf("want uncovered=[50,100], got [%d,%d]", l.QStart, l.QEnd)
	}
}

func TestTimedCache_Miss_Disjoint(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	c.Complete("k1", 100, 200, 10)

	l := c.Get("k1", 300, 400)
	if l.Status != StatusMissing {
		t.Fatalf("want StatusMissing (disjoint), got %v", l.Status)
	}
	if l.QStart != 300 || l.QEnd != 400 {
		t.Fatalf("want [300,400], got [%d,%d]", l.QStart, l.QEnd)
	}
	c.Fail("k1")
}

func TestTimedCache_AllowTimeGap(t *testing.T) {
	c := newIntCache(10, 5)
	defer c.Stop()

	c.Complete("k1", 100, 200, 10)

	// end is 203, within gap of 5 → full hit
	l := c.Get("k1", 100, 203)
	if l.Status != StatusFull {
		t.Fatalf("want StatusFull with gap, got %v", l.Status)
	}
}

func TestTimedCache_Fail_RemovesPending(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	l := c.Get("k1", 100, 200)
	if l.Status != StatusMissing {
		t.Fatalf("want StatusMissing, got %v", l.Status)
	}

	c.Fail("k1")

	l2 := c.Get("k1", 100, 200)
	if l2.Status != StatusMissing {
		t.Fatalf("after Fail, next Get should be StatusMissing again, got %v", l2.Status)
	}
	c.Fail("k1")
}

func TestTimedCache_Fail_IgnoresFilled(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	c.Complete("k1", 100, 200, 42)
	c.Fail("k1") // should be a no-op

	l := c.Get("k1", 100, 200)
	if l.Status != StatusFull {
		t.Fatalf("Fail on filled entry should be no-op, got %v", l.Status)
	}
}

func TestTimedCache_Pending_Wait(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	// goroutine A inserts a placeholder
	lA := c.Get("k1", 100, 200)
	if lA.Status != StatusMissing {
		t.Fatalf("want StatusMissing for first getter, got %v", lA.Status)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// goroutine B sees Pending, waits
		lB := c.Get("k1", 100, 200)
		if lB.Status != StatusPending {
			t.Errorf("goroutine B: want StatusPending, got %v", lB.Status)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if !lB.Wait(ctx) {
			t.Errorf("goroutine B: Wait timed out unexpectedly")
		}
	}()

	// small delay to let goroutine B block on Wait
	time.Sleep(10 * time.Millisecond)
	c.Complete("k1", 100, 200, 99)
	<-done
}

func TestTimedCache_Concurrent(t *testing.T) {
	c := newIntCache(64, 0)
	defer c.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l := c.Get("concurrent", 0, 100)
			switch l.Status {
			case StatusMissing:
				c.Complete("concurrent", 0, 100, i)
			case StatusPending:
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if !l.Wait(ctx) {
					t.Errorf("timeout waiting for load")
				}
			}
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// mergeOrdered — generic merge algorithm
// ---------------------------------------------------------------------------

func TestMergeOrdered_PureAppend(t *testing.T) {
	ts := func(v int) int64 { return int64(v) }
	a := []int{1, 2, 3}
	b := []int{5, 6, 7}
	got := mergeOrdered(a, b, ts)
	want := []int{1, 2, 3, 5, 6, 7}
	assertIntSlice(t, got, want)
}

func TestMergeOrdered_Prepend(t *testing.T) {
	ts := func(v int) int64 { return int64(v) }
	a := []int{5, 6}
	b := []int{1, 2, 3}
	got := mergeOrdered(a, b, ts)
	want := []int{1, 2, 3, 5, 6}
	assertIntSlice(t, got, want)
}

func TestMergeOrdered_RightExtend(t *testing.T) {
	ts := func(v int) int64 { return int64(v) }
	a := []int{1, 2, 3, 4}
	b := []int{3, 4, 5, 6}
	got := mergeOrdered(a, b, ts)
	want := []int{1, 2, 3, 4, 5, 6}
	assertIntSlice(t, got, want)
}

func TestMergeOrdered_LeftExtend(t *testing.T) {
	ts := func(v int) int64 { return int64(v) }
	a := []int{3, 4, 5, 6}
	b := []int{1, 2, 3, 4}
	got := mergeOrdered(a, b, ts)
	want := []int{1, 2, 3, 4, 5, 6}
	assertIntSlice(t, got, want)
}

func TestMergeOrdered_ContainsIncoming(t *testing.T) {
	ts := func(v int) int64 { return int64(v) }
	a := []int{1, 2, 3, 4, 5}
	b := []int{2, 3}
	got := mergeOrdered(a, b, ts)
	assertIntSlice(t, got, a)
}

func assertIntSlice(t *testing.T, got, want []int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("element %d: got %d, want %d (full: got %v, want %v)", i, got[i], want[i], got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// RemoteReadCache tests
// ---------------------------------------------------------------------------

func makeQuery(name string, startMs, endMs int64) *prompb.Query {
	return &prompb.Query{
		Matchers: []*prompb.LabelMatcher{{
			Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: name,
		}},
		Hints: &prompb.ReadHints{StartMs: startMs, EndMs: endMs},
	}
}

func makeReadRequest(name string, startMs, endMs int64) *prompb.ReadRequest {
	return &prompb.ReadRequest{
		Queries: []*prompb.Query{makeQuery(name, startMs, endMs)},
	}
}

func newTestResponse(lbls []prompb.Label, samples []prompb.Sample) *prompb.ReadResponse {
	return &prompb.ReadResponse{Results: []*prompb.QueryResult{{
		Timeseries: []*prompb.TimeSeries{{Labels: lbls, Samples: samples}},
	}}}
}

func TestRemoteReadCache_MissAndFullHit(t *testing.T) {
	c := NewRemoteReadCache()
	q := makeQuery("cpu", 0, 3600*1000)
	start, end := GetPromRequestQueryTime(q)

	l := c.Get(q, start, end, "", "")
	if l.Status != StatusMissing {
		t.Fatalf("want StatusMissing on first Get, got %v", l.Status)
	}

	resp := newTestResponse(
		[]prompb.Label{{Name: "__name__", Value: "cpu"}},
		[]prompb.Sample{{Timestamp: 1000, Value: 1}, {Timestamp: 2000, Value: 2}},
	)
	_ = c.Complete(makeReadRequest("cpu", 0, 3600*1000), resp, "", "")

	l2 := c.Get(q, start, end, "", "")
	if l2.Status != StatusFull {
		t.Fatalf("want StatusFull after Complete, got %v", l2.Status)
	}
	if l2.Data == nil {
		t.Fatal("want non-nil Data on full hit")
	}
	if len(l2.Data.Results[0].Timeseries) != 1 {
		t.Fatalf("want 1 timeseries, got %d", len(l2.Data.Results[0].Timeseries))
	}
}

func TestRemoteReadCache_PartialHit(t *testing.T) {
	c := NewRemoteReadCache()

	req1 := makeReadRequest("mem", 0, 3600*1000)
	resp1 := newTestResponse(
		[]prompb.Label{{Name: "__name__", Value: "mem"}},
		[]prompb.Sample{{Timestamp: 1000, Value: 1}},
	)
	_ = c.Complete(req1, resp1, "", "")

	q := makeQuery("mem", 1800*1000, 7200*1000)
	start, end := GetPromRequestQueryTime(q)
	l := c.Get(q, start, end, "", "")
	if l.Status != StatusPartial {
		t.Fatalf("want StatusPartial, got %v", l.Status)
	}
	if l.QStart >= l.QEnd {
		t.Fatalf("uncovered range invalid: [%d,%d]", l.QStart, l.QEnd)
	}
}

func TestRemoteReadCache_MergeAppendsSamples(t *testing.T) {
	c := NewRemoteReadCache()
	lbl := []prompb.Label{{Name: "__name__", Value: "net"}}

	_ = c.Complete(makeReadRequest("net", 100*1000, 200*1000),
		newTestResponse(lbl, []prompb.Sample{{Timestamp: 150, Value: 1.5}}), "", "")

	merged := c.Complete(makeReadRequest("net", 200*1000, 300*1000),
		newTestResponse(lbl, []prompb.Sample{{Timestamp: 250, Value: 2.5}}), "", "")

	ts := merged.Results[0].Timeseries[0]
	if len(ts.Samples) != 2 {
		t.Fatalf("want 2 samples, got %d", len(ts.Samples))
	}
	if ts.Samples[0].Timestamp != 150 || ts.Samples[1].Timestamp != 250 {
		t.Fatalf("unexpected sample timestamps: %v", ts.Samples)
	}
}

func TestRemoteReadCache_Fail(t *testing.T) {
	c := NewRemoteReadCache()
	req := makeReadRequest("rmkey", 0, 60*1000)
	q := req.Queries[0]
	start, end := GetPromRequestQueryTime(q)

	l := c.Get(q, start, end, "", "")
	if l.Status != StatusMissing {
		t.Fatalf("want StatusMissing, got %v", l.Status)
	}

	c.Fail(req, "", "")

	l2 := c.Get(q, start, end, "", "")
	if l2.Status != StatusMissing {
		t.Fatalf("after Fail, want StatusMissing again, got %v", l2.Status)
	}
	c.Fail(req, "", "")
}

// ---------------------------------------------------------------------------
// PromQLCache tests
// ---------------------------------------------------------------------------

func makeMatrix(metric labels.Labels, pts []promql.Point) promql.Result {
	return promql.Result{Value: promql.Matrix{
		{Metric: metric, Points: pts},
	}}
}

func makeVector(metric labels.Labels, t int64, v float64) promql.Result {
	return promql.Result{Value: promql.Vector{
		{Metric: metric, Point: promql.Point{T: t, V: v}},
	}}
}

func TestPromQLCache_MatrixMissAndHit(t *testing.T) {
	c := NewPromQLCache()
	lbl := labels.FromStrings("__name__", "bytes")

	_, _, _, required := c.Fetch("k1", 0, 60000)
	if !required {
		t.Fatal("want queryRequired=true on first Fetch")
	}

	pts := []promql.Point{{T: 10000, V: 1}, {T: 20000, V: 2}}
	if _, err := c.Complete("k1", 0, 60000, 1000, makeMatrix(lbl, pts)); err != nil {
		t.Fatalf("Complete error: %v", err)
	}

	res, fs, fe, required2 := c.Fetch("k1", 0, 60000)
	if required2 {
		t.Fatal("want queryRequired=false after Complete")
	}
	if fs != 0 || fe != 0 {
		t.Fatalf("full hit should have fixedStart=0, fixedEnd=0, got [%d,%d]", fs, fe)
	}
	m, err := res.Matrix()
	if err != nil {
		t.Fatalf("Matrix() error: %v", err)
	}
	if len(m) != 1 || len(m[0].Points) != 2 {
		t.Fatalf("unexpected matrix content: %v", m)
	}
}

func TestPromQLCache_VectorStoredAsMatrix(t *testing.T) {
	c := NewPromQLCache()
	lbl := labels.FromStrings("__name__", "up")

	_, _, _, required := c.Fetch("vec1", 1000, 1000)
	if !required {
		t.Fatal("want queryRequired on first Fetch")
	}

	if _, err := c.Complete("vec1", 1000, 1000, 0, makeVector(lbl, 1000, 3.14)); err != nil {
		t.Fatalf("Complete error: %v", err)
	}

	res, _, _, required2 := c.Fetch("vec1", 1000, 1000)
	if required2 {
		t.Fatal("want queryRequired=false after Complete")
	}
	if res.Value.Type() != parser.ValueTypeVector {
		t.Fatalf("want vector result, got %v", res.Value.Type())
	}
}

func TestPromQLCache_Fail(t *testing.T) {
	c := NewPromQLCache()

	_, _, _, required := c.Fetch("rmkey", 0, 1000)
	if !required {
		t.Fatal("want queryRequired on first Fetch")
	}

	c.Fail("rmkey")

	_, _, _, required2 := c.Fetch("rmkey", 0, 1000)
	if !required2 {
		t.Fatal("want queryRequired=true after Fail")
	}
	c.Fail("rmkey")
}

// ---------------------------------------------------------------------------
// Key utilities
// ---------------------------------------------------------------------------

func TestPromRequestToCacheKey(t *testing.T) {
	q1 := &prompb.Query{
		Matchers: []*prompb.LabelMatcher{{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "cpu"}},
		Hints:    &prompb.ReadHints{},
	}
	q2 := &prompb.Query{
		Matchers: []*prompb.LabelMatcher{{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "mem"}},
		Hints:    &prompb.ReadHints{},
	}
	k1 := promRequestToCacheKey(q1, "", "")
	k2 := promRequestToCacheKey(q2, "", "")

	if k1 == k2 {
		t.Errorf("different queries must produce different keys; both=%q", k1)
	}
	if k1 != promRequestToCacheKey(q1, "", "") {
		t.Errorf("same query must produce identical keys")
	}
}
