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

// promqlEntry bundles a promql.Result with its original value type so the cache
// can distinguish between instant (vector → stored as matrix) and range queries.
type promqlEntry struct {
	result promql.Result
	vType  parser.ValueType
}

// Cacher is a time-range cache for computed PromQL results.
// It wraps TimedCache[promqlEntry] and provides the same public API as the
// previous implementation so callers in service/promql.go are unaffected.
type Cacher struct {
	c *TimedCache[promqlEntry]
}

// NewCacher creates a Cacher configured from Cfg.
func NewCacher() *Cacher {
	cfg := config.Cfg.Prometheus.Cache
	// promql timestamps are in milliseconds, so scale the gap accordingly.
	allowGapMs := int64(cfg.CacheAllowTimeGap) * 1000
	return &Cacher{
		c: NewTimedCache(TimedCacheOptions[promqlEntry]{
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

// Fetch checks whether [start,end] is available in the cache for key.
// Returns (result, fixedStart, fixedEnd, queryRequired).
//   - queryRequired==true: caller must query and then call Merge.
//   - queryRequired==false: result is valid; fixedStart==0 && fixedEnd==0 means full hit.
func (c *Cacher) Fetch(key string, start, end int64) (r promql.Result, fixedStart int64, fixedEnd int64, queryRequired bool) {
	for {
		e, hit, qs, qe := c.c.Get(key, start, end)

		switch hit {
		case CacheKeyNotFound:
			// placeholder inserted; caller must Merge or Remove
			return promql.Result{Err: fmt.Errorf("key %s not found", key)}, start, end, true

		case CacheKeyFoundNil:
			// pending: another goroutine is loading; wait then retry via loop
			select {
			case <-time.After(time.Duration(config.Cfg.Prometheus.Cache.CacheFirstTimeout) * time.Second):
				log.Infof("req [%s:%d-%d] wait %d to get cache result", key, start, end, config.Cfg.Prometheus.Cache.CacheFirstTimeout)
				return promql.Result{Err: fmt.Errorf("key %s not found", key)}, start, end, false
			case <-e.loaded:
				// re-check after loading completes; loop back to Get
				continue
			}

		case CacheMiss:
			// range is disjoint; new placeholder was inserted
			return promql.Result{Err: fmt.Errorf("key %s not found", key)}, start, end, true

		case CacheHitFull:
			pe := e.data
			if pe.vType == parser.ValueTypeVector {
				res, ok := c.fetchInstant(pe, end)
				if ok {
					return res, start, end, false
				}
				return promql.Result{}, start, end, true
			}
			return pe.result, 0, 0, false

		case CacheHitPart:
			pe := e.data
			if pe.vType == parser.ValueTypeVector {
				// for instant queries, partial hit means the timestamp isn't in cache
				return pe.result, qs, qe, true
			}
			// range query partial hit: return the sub-range of cached data
			sub := extractSubData(pe.result, start, end)
			return sub, qs, qe, true

		default:
			return promql.Result{Err: fmt.Errorf("unexpected cache state for %s", key)}, start, end, true
		}
	}
}

// Merge stores or merges res for [start,end] into the cache entry for key.
// Returns the (merged) result as seen by callers.
func (c *Cacher) Merge(key string, start, end, step int64, res promql.Result) (promql.Result, error) {
	pe := promqlEntry{result: res, vType: res.Value.Type()}
	// vectors are stored as matrices internally for uniform merge logic
	if pe.vType == parser.ValueTypeVector {
		v, err := res.Vector()
		if err == nil {
			pe.result.Value = vectorToMatrix(&v, end)
		}
	}
	merged := c.c.Merge(key, start, end, pe)
	return merged.result, nil
}

// Remove deletes a pending-only entry (used for error cleanup).
func (c *Cacher) Remove(key string) {
	c.c.Remove(key)
}

// ---------------------------------------------------------------------------
// instant query helpers
// ---------------------------------------------------------------------------

func (c *Cacher) fetchInstant(pe promqlEntry, end int64) (promql.Result, bool) {
	samples, err := pe.result.Matrix()
	if err != nil {
		return promql.Result{Err: err}, false
	}
	if samples.Len() == 0 {
		return promql.Result{}, false
	}
	gapMs := int64(config.Cfg.Prometheus.Cache.CacheAllowTimeGap) * 1000
	result := make(promql.Vector, 0, samples.Len())
	sampleCount := 0
	for i := 0; i < samples.Len(); i++ {
		// sort.Search requires a monotonic predicate (false → true).
		// The previous predicate `T >= end && T <= end+gapMs` is false→true→false,
		// which violates the contract. Use `T >= end` (monotonic), then verify
		// the upper bound with a post-condition check.
		at := sort.Search(len(samples[i].Points), func(j int) bool {
			return samples[i].Points[j].T >= end
		})
		if at < len(samples[i].Points) && samples[i].Points[at].T <= end+gapMs {
			sampleCount++
			if samples[i].Metric != nil {
				result = append(result, promql.Sample{Metric: samples[i].Metric, Point: samples[i].Points[at]})
			}
		}
	}
	if sampleCount > 0 {
		return promql.Result{Value: result}, true
	}
	return promql.Result{}, false
}

// ---------------------------------------------------------------------------
// merge / copy / size helpers
// ---------------------------------------------------------------------------

func mergePromqlEntry(cached promqlEntry, cs, ce int64, newPe promqlEntry, ns, ne int64) promqlEntry {
	// ensure new data stored as matrix
	if newPe.vType == parser.ValueTypeVector {
		v, err := newPe.result.Vector()
		if err == nil {
			newPe.result.Value = vectorToMatrix(&v, ne)
		}
	}

	// disjoint or completely superseded — replace
	if ne <= cs || ns >= ce || (ns < cs && ne > ce) {
		return newPe
	}

	mergedResult, err := matrixMerge(newPe.result.Value.(promql.Matrix), &cached.result)
	if err != nil {
		return newPe
	}
	return promqlEntry{result: mergedResult, vType: cached.vType}
}

// mergePoints returns a new []promql.Point containing all points from both
// slices in time order, handling all four overlap cases. Never aliases either input.
func mergePoints(existing, newPts []promql.Point) []promql.Point {
	if len(existing) == 0 {
		result := make([]promql.Point, len(newPts))
		copy(result, newPts)
		return result
	}
	if len(newPts) == 0 {
		result := make([]promql.Point, len(existing))
		copy(result, existing)
		return result
	}

	existEnd := existing[len(existing)-1].T
	existStart := existing[0].T
	newEnd := newPts[len(newPts)-1].T

	if existEnd < newPts[0].T {
		// existing: [   ]
		// new:             [   ]
		result := make([]promql.Point, len(existing)+len(newPts))
		copy(result, existing)
		copy(result[len(existing):], newPts)
		return result
	} else if existStart > newEnd {
		// existing:        [   ]
		// new:      [   ]
		result := make([]promql.Point, len(newPts)+len(existing))
		copy(result, newPts)
		copy(result[len(newPts):], existing)
		return result
	} else if existEnd >= newPts[0].T && existEnd < newEnd {
		// existing: [   ]
		// new:        [   ]
		at := sort.Search(len(newPts), func(i int) bool {
			return newPts[i].T > existEnd
		})
		result := make([]promql.Point, len(existing)+(len(newPts)-at))
		copy(result, existing)
		copy(result[len(existing):], newPts[at:])
		return result
	} else if existStart <= newEnd && existStart > newPts[0].T {
		// existing:   [   ]
		// new:      [   ]
		at := sort.Search(len(newPts), func(i int) bool {
			return newPts[i].T >= existStart
		})
		result := make([]promql.Point, at+len(existing))
		copy(result, newPts[:at])
		copy(result[at:], existing)
		return result
	}
	// existing completely contains new (or identical); keep existing
	result := make([]promql.Point, len(existing))
	copy(result, existing)
	return result
}

func matrixMerge(resp promql.Matrix, cache *promql.Result) (promql.Result, error) {
	cacheMatrix, err := cache.Matrix()
	if err != nil {
		return promql.Result{Err: err}, err
	}

	// Build result as fresh allocations so MergeFn never aliases cached data.
	result := make(promql.Matrix, len(cacheMatrix))
	for i, s := range cacheMatrix {
		pts := make([]promql.Point, len(s.Points))
		copy(pts, s.Points)
		result[i] = promql.Series{Metric: s.Metric, Points: pts}
	}

	appendMatrix := make([]promql.Series, 0, len(resp))
	for _, series := range resp {
		matched := false
		// Use indexed iteration (not range-copy) so mutations to result[i].Points
		// are actually persisted — a range-copy would silently discard them.
		for i := range result {
			if result[i].Metric != nil && promLabelsEqual(&result[i].Metric, &series.Metric) {
				result[i].Points = mergePoints(result[i].Points, series.Points)
				matched = true
				break
			}
		}
		if !matched {
			appendMatrix = append(appendMatrix, series)
		}
	}
	if len(appendMatrix) > 0 {
		result = append(result, appendMatrix...)
	}
	return promql.Result{Value: result}, nil
}

func extractSubData(r promql.Result, start, end int64) promql.Result {
	matrix, err := r.Matrix()
	if err != nil {
		return promql.Result{Err: err}
	}
	result := make(promql.Matrix, 0, len(matrix))
	for _, series := range matrix {
		begin := sort.Search(len(series.Points), func(i int) bool {
			return series.Points[i].T >= start
		})
		stop := sort.Search(len(series.Points), func(i int) bool {
			return series.Points[i].T > end
		})
		pts := make([]promql.Point, stop-begin)
		copy(pts, series.Points[begin:stop])
		result = append(result, promql.Series{Metric: series.Metric, Points: pts})
	}
	return promql.Result{Value: result}
}

func vectorToMatrix(v *promql.Vector, t int64) promql.Matrix {
	output := make(promql.Matrix, 0, len(*v))
	for _, m := range *v {
		output = append(output, promql.Series{
			Metric: m.Metric,
			Points: []promql.Point{m.Point},
		})
	}
	if len(*v) == 0 {
		output = append(output, promql.Series{
			Metric: nil,
			Points: []promql.Point{{T: t, V: 0}},
		})
	}
	return output
}

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
			size += unsafe.Sizeof((*string)(unsafe.Pointer(&v.Name))) +
				unsafe.Sizeof((*string)(unsafe.Pointer(&v.Value)))
		}
		totalPoints += len(m.Points)
	}
	size += uintptr(totalPoints*pointSize + totalPoints*pointPtrSize)
	return uint64(size)
}

