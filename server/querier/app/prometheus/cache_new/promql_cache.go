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
	"fmt"
	"sort"
	"time"
	"unsafe"

	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
)

const (
	pointSize    = int(unsafe.Sizeof(promql.Point{}))
	pointPtrSize = int(unsafe.Sizeof(&promql.Point{}))
)

// PromQLCache is a time-range cache for computed PromQL results.
// It stores promqlEntry (result + original value type) keyed by a
// caller-supplied string. Vectors are converted to matrices on store
// so that merge and copy logic is uniform across all value types.
type PromQLCache struct {
	c *TimedCache[promqlEntry]
}

// NewPromQLCache creates a PromQLCache configured from Cfg.
func NewPromQLCache() *PromQLCache {
	cfg := config.Cfg.Prometheus.Cache
	// PromQL timestamps are in milliseconds; scale the gap accordingly.
	allowGapMs := int64(cfg.CacheAllowTimeGap) * 1000
	return &PromQLCache{
		c: NewTimedCache(Options[promqlEntry]{
			MaxCount:      cfg.CacheMaxCount,
			MaxItemSize:   cfg.CacheItemSize,
			CleanInterval: time.Duration(cfg.CacheCleanInterval) * time.Second,
			AllowTimeGap:  allowGapMs,
			MergeFn:       mergePromqlEntry,
			CopyFn:        copyPromqlEntry,
			SizeFn:        sizeofPromqlEntry,
		}),
	}
}

// Fetch checks whether [start, end] is available in the cache for key.
//
// Returns (result, qStart, qEnd, queryRequired):
//   - queryRequired == false: result is valid; callers should return it directly.
//   - queryRequired == true: caller must query [qStart, qEnd] then call Complete.
//
// When another goroutine is loading the same key, Fetch blocks up to the
// configured CacheFirstTimeout before returning (queryRequired=false, empty result).
func (c *PromQLCache) Fetch(key string, start, end int64) (promql.Result, int64, int64, bool) {
	timeout := time.Duration(config.Cfg.Prometheus.Cache.CacheFirstTimeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		lookup := c.c.Get(key, start, end)

		switch lookup.Status {
		case StatusMissing:
			// placeholder inserted; caller must Complete or Fail
			return promql.Result{Err: fmt.Errorf("cache miss for %s", key)}, start, end, true

		case StatusPending:
			// another goroutine is loading; wait then retry
			if !lookup.Wait(ctx) {
				log.Infof("req [%s:%d-%d] timed out waiting for cache load", key, start, end)
				return promql.Result{}, start, end, false
			}
			continue // re-check after the load completes

		case StatusFull:
			pe := lookup.Data
			if pe.vType == parser.ValueTypeVector {
				res, ok := c.fetchInstant(pe, end)
				if ok {
					return res, start, end, false
				}
				// timestamp not in cache (shouldn't happen, but be safe)
				return promql.Result{}, start, end, true
			}
			return pe.result, 0, 0, false

		case StatusPartial:
			pe := lookup.Data
			if pe.vType == parser.ValueTypeVector {
				// instant queries: partial hit means the timestamp isn't cached
				return pe.result, lookup.QStart, lookup.QEnd, true
			}
			// range query partial hit: extract the cached portion and query the rest
			sub := extractSubData(pe.result, start, end)
			return sub, lookup.QStart, lookup.QEnd, true
		}
	}
}

// Complete stores or merges res for [start, end] into the cache under key.
// Returns the (merged) result.
func (c *PromQLCache) Complete(key string, start, end, step int64, res promql.Result) (promql.Result, error) {
	pe := promqlEntry{result: res, vType: res.Value.Type()}
	// store vectors as matrices so merge logic is uniform
	if pe.vType == parser.ValueTypeVector {
		v, err := res.Vector()
		if err == nil {
			pe.result.Value = vectorToMatrix(&v, end)
		}
	}
	merged := c.c.Complete(key, start, end, pe)
	return merged.result, nil
}

// Fail removes a pending placeholder for key, unblocking any waiters.
func (c *PromQLCache) Fail(key string) {
	c.c.Fail(key)
}

// ---------------------------------------------------------------------------
// instant query helper
// ---------------------------------------------------------------------------

func (c *PromQLCache) fetchInstant(pe promqlEntry, end int64) (promql.Result, bool) {
	samples, err := pe.result.Matrix()
	if err != nil {
		return promql.Result{Err: err}, false
	}
	if samples.Len() == 0 {
		return promql.Result{}, false
	}

	gapMs := int64(config.Cfg.Prometheus.Cache.CacheAllowTimeGap) * 1000
	result := make(promql.Vector, 0, samples.Len())
	found := 0

	for i := 0; i < samples.Len(); i++ {
		// sort.Search requires a monotone predicate (false→true).
		// Use T >= end (monotone), then post-check the upper bound.
		at := sort.Search(len(samples[i].Points), func(j int) bool {
			return samples[i].Points[j].T >= end
		})
		if at < len(samples[i].Points) && samples[i].Points[at].T <= end+gapMs {
			found++
			if samples[i].Metric != nil {
				result = append(result, promql.Sample{
					Metric: samples[i].Metric,
					Point:  samples[i].Points[at],
				})
			}
		}
	}

	if found > 0 {
		return promql.Result{Value: result}, true
	}
	return promql.Result{}, false
}

// ---------------------------------------------------------------------------
// copy / size / extract helpers
// ---------------------------------------------------------------------------

func copyPromqlEntry(pe promqlEntry) promqlEntry {
	if pe.result.Value == nil {
		return pe
	}
	matrix, err := pe.result.Matrix()
	if err != nil {
		return pe
	}
	copied := make(promql.Matrix, len(matrix))
	for i, series := range matrix {
		pts := make([]promql.Point, len(series.Points))
		copy(pts, series.Points)
		copied[i] = promql.Series{Metric: series.Metric, Points: pts}
	}
	return promqlEntry{result: promql.Result{Value: copied}, vType: pe.vType}
}

func sizeofPromqlEntry(pe promqlEntry) uint64 {
	matrix, err := pe.result.Matrix()
	if err != nil {
		return 0
	}
	var size uintptr
	totalPoints := 0
	for _, m := range matrix {
		for _, v := range m.Metric {
			size += uintptr(len(v.Name) + len(v.Value))
			size += unsafe.Sizeof(v.Name) + unsafe.Sizeof(v.Value)
		}
		totalPoints += len(m.Points)
	}
	size += uintptr(totalPoints * (pointSize + pointPtrSize))
	return uint64(size)
}

// extractSubData slices the cached matrix to the intersection of [start, end]
// with the cached range, returning a fresh result with no aliased Points.
func extractSubData(r promql.Result, start, end int64) promql.Result {
	matrix, err := r.Matrix()
	if err != nil {
		return promql.Result{Err: err}
	}
	result := make(promql.Matrix, 0, len(matrix))
	for _, series := range matrix {
		lo := sort.Search(len(series.Points), func(i int) bool { return series.Points[i].T >= start })
		hi := sort.Search(len(series.Points), func(i int) bool { return series.Points[i].T > end })
		pts := make([]promql.Point, hi-lo)
		copy(pts, series.Points[lo:hi])
		result = append(result, promql.Series{Metric: series.Metric, Points: pts})
	}
	return promql.Result{Value: result}
}
