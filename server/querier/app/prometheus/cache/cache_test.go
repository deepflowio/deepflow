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

package cache

import (
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

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

func TestMain(m *testing.M) {
	config.Cfg = &config.QuerierConfig{Prometheus: cfg.Prometheus{Cache: cfg.PrometheusCache{
		RemoteReadCache:    true,
		CacheItemSize:      512 * 1024 * 1024, // 512 MiB — don't evict in tests
		CacheMaxCount:      128,
		CacheFirstTimeout:  5,
		CacheCleanInterval: 3600,
		CacheAllowTimeGap:  1,
	}}}
	m.Run()
}

// ---------------------------------------------------------------------------
// TimedCache[int] — generic foundation unit tests
// ---------------------------------------------------------------------------

func newIntCache(maxCount int, allowGap int64) *TimedCache[int] {
	return NewTimedCache(TimedCacheOptions[int]{
		MaxCount:      maxCount,
		MaxItemSize:   ^uint64(0), // never evict
		CleanInterval: time.Hour,
		AllowTimeGap:  allowGap,
		MergeFn: func(cached int, cs, ce int64, newData int, ns, ne int64) int {
			return cached + newData
		},
		CopyFn: func(v int) int { return v },
		SizeFn: func(v int) uint64 { return 8 },
	})
}

func TestTimedCache_KeyNotFound(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	e, hit, qs, qe := c.Get("k1", 100, 200)
	if hit != CacheKeyNotFound {
		t.Fatalf("expected CacheKeyNotFound, got %v", hit)
	}
	if qs != 100 || qe != 200 {
		t.Fatalf("expected [100,200], got [%d,%d]", qs, qe)
	}
	// placeholder inserted — clean it up
	c.Remove("k1")
	_ = e
}

func TestTimedCache_MergeThenFullHit(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	// first get inserts placeholder
	e, hit, _, _ := c.Get("k1", 100, 200)
	if hit != CacheKeyNotFound {
		t.Fatalf("expected CacheKeyNotFound, got %v", hit)
	}
	_ = e

	// merge data
	stored := c.Merge("k1", 100, 200, 42)
	if stored != 42 {
		t.Fatalf("expected stored=42, got %d", stored)
	}

	// second get should be full hit
	e2, hit2, _, _ := c.Get("k1", 110, 190)
	if hit2 != CacheHitFull {
		t.Fatalf("expected CacheHitFull, got %v", hit2)
	}
	if e2.data != 42 {
		t.Fatalf("expected data=42, got %d", e2.data)
	}
}

func TestTimedCache_PartialHit_Right(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	c.Merge("k1", 100, 200, 10)

	e, hit, qs, qe := c.Get("k1", 150, 300)
	if hit != CacheHitPart {
		t.Fatalf("expected CacheHitPart, got %v", hit)
	}
	if qs != 200 || qe != 300 {
		t.Fatalf("expected query [200,300], got [%d,%d]", qs, qe)
	}
	_ = e
}

func TestTimedCache_PartialHit_Left(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	c.Merge("k1", 100, 200, 10)

	e, hit, qs, qe := c.Get("k1", 50, 150)
	if hit != CacheHitPart {
		t.Fatalf("expected CacheHitPart, got %v", hit)
	}
	if qs != 50 || qe != 100 {
		t.Fatalf("expected query [50,100], got [%d,%d]", qs, qe)
	}
	_ = e
}

func TestTimedCache_Miss_Disjoint(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	c.Merge("k1", 100, 200, 10)

	_, hit, qs, qe := c.Get("k1", 300, 400)
	if hit != CacheMiss {
		t.Fatalf("expected CacheMiss, got %v", hit)
	}
	if qs != 300 || qe != 400 {
		t.Fatalf("expected query [300,400], got [%d,%d]", qs, qe)
	}
}

func TestTimedCache_AllowTimeGap_FullHit(t *testing.T) {
	c := newIntCache(10, 5) // 5s gap
	defer c.Stop()

	c.Merge("k1", 100, 200, 10)

	// query end is 203, within gap of 5 → treated as full hit
	_, hit, _, _ := c.Get("k1", 100, 203)
	if hit != CacheHitFull {
		t.Fatalf("expected CacheHitFull with gap, got %v", hit)
	}
}

func TestTimedCache_Remove_OnlyPending(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	// insert placeholder
	_, hit, _, _ := c.Get("k1", 100, 200)
	if hit != CacheKeyNotFound {
		t.Fatalf("want CacheKeyNotFound, got %v", hit)
	}

	// remove it (pending → zero)
	c.Remove("k1")

	// should be gone: next get inserts a new placeholder
	_, hit2, _, _ := c.Get("k1", 100, 200)
	if hit2 != CacheKeyNotFound {
		t.Fatalf("want CacheKeyNotFound after remove, got %v", hit2)
	}
	c.Remove("k1")
}

func TestTimedCache_Remove_IgnoresNonPending(t *testing.T) {
	c := newIntCache(10, 0)
	defer c.Stop()

	c.Merge("k1", 100, 200, 42)

	// Remove should be a no-op for a real entry
	c.Remove("k1")

	_, hit, _, _ := c.Get("k1", 100, 200)
	if hit != CacheHitFull {
		t.Fatalf("expected data still present, got %v", hit)
	}
}

func TestTimedCache_Concurrent(t *testing.T) {
	c := newIntCache(64, 0)
	defer c.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "concurrent"
			e, hit, _, _ := c.Get(key, 0, 100)
			if hit == CacheKeyNotFound {
				c.Merge(key, 0, 100, i)
			} else if hit == CacheKeyFoundNil {
				select {
				case <-e.loaded:
				case <-time.After(2 * time.Second):
					t.Errorf("timeout waiting for loaded signal")
				}
			}
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// RemoteReadQueryCache tests
// ---------------------------------------------------------------------------

func newTestReadResponse(labels []prompb.Label, samples []prompb.Sample) *prompb.ReadResponse {
	return &prompb.ReadResponse{
		Results: []*prompb.QueryResult{{
			Timeseries: []*prompb.TimeSeries{{Labels: labels, Samples: samples}},
		}},
	}
}

func makeQuery(name, value string, startMs, endMs int64) *prompb.Query {
	return &prompb.Query{
		Matchers: []*prompb.LabelMatcher{{
			Type:  prompb.LabelMatcher_EQ,
			Name:  "__name__",
			Value: name,
		}},
		Hints: &prompb.ReadHints{
			StartMs: startMs,
			EndMs:   endMs,
			Func:    value,
		},
	}
}

func makeReadRequest(name string, startMs, endMs int64) *prompb.ReadRequest {
	return &prompb.ReadRequest{
		Queries: []*prompb.Query{makeQuery(name, "", startMs, endMs)},
	}
}

func TestRemoteReadCache_MissAndFullHit(t *testing.T) {
	cache := NewRemoteReadQueryCache()

	q := makeQuery("cpu", "", 0, 3600*1000)
	start, end := GetPromRequestQueryTime(q)

	item, hit, _, _ := cache.Get(q, start, end, "", "")
	if hit != CacheKeyNotFound {
		t.Fatalf("expected CacheKeyNotFound, got %v", hit)
	}
	_ = item

	resp := newTestReadResponse(
		[]prompb.Label{{Name: "__name__", Value: "cpu"}},
		[]prompb.Sample{{Timestamp: 1000, Value: 1.0}, {Timestamp: 2000, Value: 2.0}},
	)
	req := makeReadRequest("cpu", 0, 3600*1000)
	_ = cache.AddOrMerge(req, resp, "", "")

	item2, hit2, _, _ := cache.Get(q, start, end, "", "")
	if hit2 != CacheHitFull {
		t.Fatalf("expected CacheHitFull, got %v", hit2)
	}
	data := item2.Data()
	if data == nil {
		t.Fatal("expected non-nil data on full hit")
	}
	if len(data.Results[0].Timeseries) != 1 {
		t.Fatalf("expected 1 timeseries, got %d", len(data.Results[0].Timeseries))
	}
}

func TestRemoteReadCache_PartialMerge(t *testing.T) {
	cache := NewRemoteReadQueryCache()

	// store [0, 3600]
	req1 := makeReadRequest("mem", 0, 3600*1000)
	resp1 := newTestReadResponse(
		[]prompb.Label{{Name: "__name__", Value: "mem"}},
		[]prompb.Sample{{Timestamp: 1000, Value: 1.0}, {Timestamp: 2000, Value: 2.0}},
	)
	_ = cache.AddOrMerge(req1, resp1, "", "")

	// query [1800, 7200] → partial hit, missing [3600,7200]
	q := makeQuery("mem", "", 1800*1000, 7200*1000)
	start, end := GetPromRequestQueryTime(q)
	_, hit, partQS, partQE := cache.Get(q, start, end, "", "")
	if hit != CacheHitPart {
		t.Fatalf("expected CacheHitPart, got %v", hit)
	}
	if partQS >= partQE {
		t.Fatalf("partial query range invalid: [%d,%d]", partQS, partQE)
	}
}

func TestRemoteReadCache_MergeAppendsNewSamples(t *testing.T) {
	c := NewRemoteReadQueryCache()
	lbl := []prompb.Label{{Name: "__name__", Value: "net"}}

	// store [100, 200] with samples at t=150
	req1 := makeReadRequest("net", 100*1000, 200*1000)
	resp1 := newTestReadResponse(lbl, []prompb.Sample{{Timestamp: 150, Value: 1.5}})
	_ = c.AddOrMerge(req1, resp1, "", "")

	// merge [200, 300] with samples at t=250
	req2 := makeReadRequest("net", 200*1000, 300*1000)
	resp2 := newTestReadResponse(lbl, []prompb.Sample{{Timestamp: 250, Value: 2.5}})
	merged := c.AddOrMerge(req2, resp2, "", "")

	ts := merged.Results[0].Timeseries[0]
	if len(ts.Samples) != 2 {
		t.Fatalf("expected 2 samples after merge, got %d", len(ts.Samples))
	}
	if ts.Samples[0].Timestamp != 150 || ts.Samples[1].Timestamp != 250 {
		t.Fatalf("unexpected sample timestamps: %v", ts.Samples)
	}
}

func TestRemoteReadCache_NoCAACHE_LABEL_IN_RESULT(t *testing.T) {
	// Verify that the internal fingerprint label is not leaked to callers.
	c := NewRemoteReadQueryCache()
	lbl := []prompb.Label{
		{Name: "__name__", Value: "check"},
		{Name: "instance", Value: "localhost"},
	}
	req := makeReadRequest("check", 0, 60*1000)
	resp := newTestReadResponse(lbl, []prompb.Sample{{Timestamp: 10, Value: 1}})
	result := c.AddOrMerge(req, resp, "", "")

	for _, ts := range result.Results[0].Timeseries {
		for _, l := range ts.Labels {
			if l.Name == "__cache_label_string__" {
				t.Errorf("CACHE_LABEL_STRING_TAG leaked into result labels")
			}
		}
	}
}

func TestRemoteReadCache_Remove(t *testing.T) {
	c := NewRemoteReadQueryCache()

	req := makeReadRequest("removeme", 0, 60*1000)
	q := req.Queries[0]
	start, end := GetPromRequestQueryTime(q)

	_, hit, _, _ := c.Get(q, start, end, "", "")
	if hit != CacheKeyNotFound {
		t.Fatalf("expected miss, got %v", hit)
	}

	// remove the pending placeholder
	c.Remove(req, "", "")

	// next get should again be a miss (new placeholder)
	_, hit2, _, _ := c.Get(q, start, end, "", "")
	if hit2 != CacheKeyNotFound {
		t.Fatalf("expected miss after remove, got %v", hit2)
	}
	c.Remove(req, "", "")
}

// ---------------------------------------------------------------------------
// Cacher (promql.Result) tests
// ---------------------------------------------------------------------------

func makeMatrix(metric labels.Labels, points []promql.Point) promql.Result {
	return promql.Result{Value: promql.Matrix{
		promql.Series{Metric: metric, Points: points},
	}}
}

func makeVector(metric labels.Labels, t int64, v float64) promql.Result {
	return promql.Result{Value: promql.Vector{
		promql.Sample{Metric: metric, Point: promql.Point{T: t, V: v}},
	}}
}

func TestCacher_MatrixMissAndHit(t *testing.T) {
	c := NewCacher()
	lbl := labels.FromStrings("__name__", "bytes")

	// first fetch: queryRequired == true
	_, _, _, required := c.Fetch("k1", 0, 60000)
	if !required {
		t.Fatal("expected queryRequired=true on first fetch")
	}

	pts := []promql.Point{{T: 10000, V: 1}, {T: 20000, V: 2}}
	_, err := c.Merge("k1", 0, 60000, 1000, makeMatrix(lbl, pts))
	if err != nil {
		t.Fatalf("Merge error: %v", err)
	}

	res, fs, fe, required2 := c.Fetch("k1", 0, 60000)
	if required2 {
		t.Fatal("expected queryRequired=false on second fetch")
	}
	if fs != 0 || fe != 0 {
		t.Fatalf("expected fixedStart=0, fixedEnd=0 for full hit, got [%d,%d]", fs, fe)
	}
	m, err := res.Matrix()
	if err != nil {
		t.Fatalf("Matrix() error: %v", err)
	}
	if len(m) != 1 || len(m[0].Points) != 2 {
		t.Fatalf("unexpected matrix content: %v", m)
	}
}

func TestCacher_VectorStoredAsMatrix(t *testing.T) {
	c := NewCacher()
	lbl := labels.FromStrings("__name__", "up")

	_, _, _, required := c.Fetch("vec1", 1000, 1000)
	if !required {
		t.Fatal("expected queryRequired on first fetch")
	}

	vec := makeVector(lbl, 1000, 3.14)
	_, err := c.Merge("vec1", 1000, 1000, 0, vec)
	if err != nil {
		t.Fatalf("Merge error: %v", err)
	}

	res, _, _, required2 := c.Fetch("vec1", 1000, 1000)
	if required2 {
		t.Fatal("expected queryRequired=false after merge")
	}
	if res.Value.Type() != parser.ValueTypeVector {
		t.Fatalf("expected vector result, got %v", res.Value.Type())
	}
}

func TestCacher_Remove(t *testing.T) {
	c := NewCacher()

	_, _, _, required := c.Fetch("rmkey", 0, 1000)
	if !required {
		t.Fatal("expected queryRequired on first fetch")
	}

	c.Remove("rmkey")

	_, _, _, required2 := c.Fetch("rmkey", 0, 1000)
	if !required2 {
		t.Fatal("expected queryRequired after remove")
	}
	c.Remove("rmkey")
}

// ---------------------------------------------------------------------------
// promRequestToCacheKey tests
// ---------------------------------------------------------------------------

func TestPromRequestToCacheKey(t *testing.T) {
	q1 := &prompb.Query{
		Matchers: []*prompb.LabelMatcher{
			{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "cpu"},
		},
		Hints: &prompb.ReadHints{StartMs: 0, EndMs: 60000},
	}
	q2 := &prompb.Query{
		Matchers: []*prompb.LabelMatcher{
			{Type: prompb.LabelMatcher_EQ, Name: "__name__", Value: "mem"},
		},
		Hints: &prompb.ReadHints{StartMs: 0, EndMs: 60000},
	}

	k1 := promRequestToCacheKey(q1, "", "")
	k2 := promRequestToCacheKey(q2, "", "")
	if k1 == k2 {
		t.Errorf("different queries should produce different keys; both=%q", k1)
	}
	if k1 == "" || k2 == "" {
		t.Errorf("keys must be non-empty")
	}

	// same query → same key
	k1b := promRequestToCacheKey(q1, "", "")
	if k1 != k1b {
		t.Errorf("same query should produce same key: %q != %q", k1, k1b)
	}
}
