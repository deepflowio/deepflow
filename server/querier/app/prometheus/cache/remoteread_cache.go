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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/statsd"
	"github.com/prometheus/prometheus/prompb"
)

const (
	sampleSize    = int(unsafe.Sizeof(prompb.Sample{}))
	samplePtrSize = int(unsafe.Sizeof(&prompb.Sample{}))
)

// RemoteReadQueryCache is a time-range cache for raw Prometheus timeseries data.
// It wraps TimedCache[*prompb.ReadResponse] and provides the same public API as
// the previous implementation so callers in service/remote_read.go are unaffected.
type RemoteReadQueryCache struct {
	c       *TimedCache[*prompb.ReadResponse]
	counter *CacheCounter
}

var (
	readResponseCache *RemoteReadQueryCache
	syncOnce          sync.Once
)

// PromReadResponseCache returns the process-wide singleton RemoteReadQueryCache.
func PromReadResponseCache() *RemoteReadQueryCache {
	syncOnce.Do(func() {
		readResponseCache = NewRemoteReadQueryCache()
	})
	return readResponseCache
}

// NewRemoteReadQueryCache creates a RemoteReadQueryCache configured from Cfg.
func NewRemoteReadQueryCache() *RemoteReadQueryCache {
	cfg := config.Cfg.Prometheus.Cache
	r := &RemoteReadQueryCache{
		counter: &CacheCounter{Stats: &CacheStats{}},
	}
	r.c = NewTimedCache(TimedCacheOptions[*prompb.ReadResponse]{
		MaxCount:      cfg.CacheMaxCount,
		MaxItemSize:   cfg.CacheItemSize,
		CleanInterval: time.Duration(cfg.CacheCleanInterval) * time.Second,
		AllowTimeGap:  int64(cfg.CacheAllowTimeGap),
		MergeFn:       mergePrompbResponse,
		CopyFn:        copyPrompbResponse,
		SizeFn:        sizeofPrompbResponse,
	})
	statsd.RegisterCountableForIngester("prometheus_cache_counter", r.counter)
	return r
}

// Get checks whether the cache covers [start,end] for the given query.
// Returns (cacheItem, hitType, adjustedStart, adjustedEnd).
// When hitType == CacheKeyNotFound or CacheMiss the caller must later call
// AddOrMerge (or Remove on error) to unblock any concurrent waiters.
func (r *RemoteReadQueryCache) Get(req *prompb.Query, start, end int64, orgFilter, extraFilters string) (*CacheItem, CacheHit, int64, int64) {
	if req.Hints.Func == "series" {
		return nil, CacheMiss, start, end
	}

	key := promRequestToCacheKey(req, orgFilter, extraFilters)
	start = timeAlign(start)

	e, hit, qs, qe := r.c.Get(key, start, end)

	switch hit {
	case CacheKeyNotFound:
		atomic.AddUint64(&r.counter.Stats.CacheMiss, 1)
		return &CacheItem{e: e}, CacheKeyNotFound, qs, qe
	case CacheKeyFoundNil:
		return &CacheItem{e: e}, CacheKeyFoundNil, qs, qe
	case CacheMiss:
		atomic.AddUint64(&r.counter.Stats.CacheMiss, 1)
		return nil, CacheMiss, qs, qe
	case CacheHitFull:
		atomic.AddUint64(&r.counter.Stats.CacheHit, 1)
		return &CacheItem{e: e}, CacheHitFull, qs, qe
	case CacheHitPart:
		atomic.AddUint64(&r.counter.Stats.CacheHit, 1)
		return &CacheItem{e: e}, CacheHitPart, qs, qe
	default:
		return nil, CacheMiss, start, end
	}
}

// AddOrMerge stores or merges resp for the query's time range into the cache.
// Returns a deep copy of the merged result (safe to return to callers).
func (r *RemoteReadQueryCache) AddOrMerge(req *prompb.ReadRequest, resp *prompb.ReadResponse, orgFilter, extraFilters string) *prompb.ReadResponse {
	if req == nil || len(req.Queries) == 0 {
		return resp
	}
	if resp == nil || len(resp.Results) == 0 {
		return resp
	}
	q := req.Queries[0]
	if q.Hints.Func == "series" {
		return resp
	}

	key := promRequestToCacheKey(q, orgFilter, extraFilters)
	start, end := GetPromRequestQueryTime(q)
	start = timeAlign(start)

	atomic.AddUint64(&r.counter.Stats.CacheMerge, 1)
	t0 := time.Now()
	result := r.c.Merge(key, start, end, resp)
	atomic.AddUint64(&r.counter.Stats.CacheMergeDuration, uint64(time.Since(t0).Seconds()))
	return result
}

// Remove deletes a pending-only entry (used for error cleanup).
func (r *RemoteReadQueryCache) Remove(req *prompb.ReadRequest, orgFilter, extraFilter string) {
	if req == nil || len(req.Queries) == 0 {
		return
	}
	key := promRequestToCacheKey(req.Queries[0], orgFilter, extraFilter)
	r.c.Remove(key)
}

// CacheItem is a thin view into a timed_cache entry for RemoteRead callers.
type CacheItem struct {
	e *entry[*prompb.ReadResponse]
}

// Data returns the cached ReadResponse (already deep-copied by TimedCache).
func (c *CacheItem) Data() *prompb.ReadResponse {
	if c == nil || c.e == nil {
		return nil
	}
	return c.e.data
}

// GetLoadCompleteSignal returns the channel that closes when loading finishes.
func (c *CacheItem) GetLoadCompleteSignal() chan struct{} {
	if c == nil || c.e == nil {
		return nil
	}
	return c.e.loaded
}

// ---------------------------------------------------------------------------
// merge / copy / size helpers
// ---------------------------------------------------------------------------

// labelFingerprint builds a stable string key from a prompb.Label slice.
// Labels are sorted by name (then value) before hashing so that the same
// metric set produces an identical fingerprint regardless of the iteration
// order used by the caller (e.g. from map-based label construction).
func labelFingerprint(labels []prompb.Label) string {
	sorted := make([]prompb.Label, len(labels))
	copy(sorted, labels)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Value < sorted[j].Value
	})
	var b strings.Builder
	for i := range sorted {
		b.WriteString(sorted[i].Name)
		b.WriteByte('=')
		b.WriteString(sorted[i].Value)
		b.WriteByte(',')
	}
	return b.String()
}

// mergeSamples returns a new []prompb.Sample that merges existing and newSamples
// by timestamp order, handling all four overlap cases. Never aliases either input.
func mergeSamples(existing, newSamples []prompb.Sample) []prompb.Sample {
	if len(existing) == 0 {
		result := make([]prompb.Sample, len(newSamples))
		copy(result, newSamples)
		return result
	}
	if len(newSamples) == 0 {
		result := make([]prompb.Sample, len(existing))
		copy(result, existing)
		return result
	}

	existStart := existing[0].Timestamp
	existEnd := existing[len(existing)-1].Timestamp
	newEnd := newSamples[len(newSamples)-1].Timestamp

	if existEnd < newSamples[0].Timestamp {
		// existing: [   ]
		// new:             [   ]
		result := make([]prompb.Sample, len(existing)+len(newSamples))
		copy(result, existing)
		copy(result[len(existing):], newSamples)
		return result
	} else if existStart > newEnd {
		// existing:        [   ]
		// new:      [   ]
		result := make([]prompb.Sample, len(newSamples)+len(existing))
		copy(result, newSamples)
		copy(result[len(newSamples):], existing)
		return result
	} else if existEnd >= newSamples[0].Timestamp && existEnd < newEnd {
		// existing: [   ]
		// new:        [   ]
		overlapAt := sort.Search(len(newSamples), func(i int) bool {
			return newSamples[i].Timestamp > existEnd
		})
		result := make([]prompb.Sample, len(existing)+(len(newSamples)-overlapAt))
		copy(result, existing)
		copy(result[len(existing):], newSamples[overlapAt:])
		return result
	} else if existStart <= newEnd && existStart > newSamples[0].Timestamp {
		// existing:   [   ]
		// new:      [   ]
		overlapAt := sort.Search(len(newSamples), func(i int) bool {
			return newSamples[i].Timestamp >= existStart
		})
		result := make([]prompb.Sample, overlapAt+len(existing))
		copy(result, newSamples[:overlapAt])
		copy(result[overlapAt:], existing)
		return result
	}
	// existing completely contains new (or identical); keep existing
	result := make([]prompb.Sample, len(existing))
	copy(result, existing)
	return result
}

// mergePrompbResponse merges newData (covering [ns,ne]) into cached (covering [cs,ce]).
// Returns a completely fresh *prompb.ReadResponse — never mutates or aliases cached.
func mergePrompbResponse(cached *prompb.ReadResponse, cs, ce int64, newData *prompb.ReadResponse, ns, ne int64) *prompb.ReadResponse {
	log.Debugf("cache merged, new range: [%d-%d], cached range: [%d-%d]", ns, ne, cs, ce)

	if newData == nil || len(newData.Results) == 0 {
		return cached
	}
	if cached == nil || len(cached.Results) == 0 {
		return newData
	}

	// query fully inside cache — nothing to add
	if ns >= cs && ne <= ce {
		return cached
	}

	// query wider than cache on both sides — replace
	if ns < cs && ne > ce {
		return newData
	}

	// disjoint — replace
	if ne <= cs || ns >= ce {
		return newData
	}

	// partial overlap: merge by label fingerprint
	queryTs := newData.Results[0].Timeseries
	cachedTs := cached.Results[0].Timeseries

	// build fingerprint→index map for cached series
	fpIndex := make(map[string]int, len(cachedTs))
	for i, ts := range cachedTs {
		fpIndex[labelFingerprint(ts.Labels)] = i
	}

	// Deep-copy all cached series into the result slice upfront.
	// Matched entries will have their Samples replaced with a fresh merged slice.
	mergedTs := make([]*prompb.TimeSeries, len(cachedTs))
	for i, ts := range cachedTs {
		newLabels := make([]prompb.Label, len(ts.Labels))
		copy(newLabels, ts.Labels)
		newSamples := make([]prompb.Sample, len(ts.Samples))
		copy(newSamples, ts.Samples)
		mergedTs[i] = &prompb.TimeSeries{Labels: newLabels, Samples: newSamples}
	}

	appendTs := make([]*prompb.TimeSeries, 0)
	for _, newTs := range queryTs {
		fp := labelFingerprint(newTs.Labels)
		idx, found := fpIndex[fp]
		if !found {
			// Deep-copy the new series; do not alias newData.
			newLabels := make([]prompb.Label, len(newTs.Labels))
			copy(newLabels, newTs.Labels)
			newSamples := make([]prompb.Sample, len(newTs.Samples))
			copy(newSamples, newTs.Samples)
			appendTs = append(appendTs, &prompb.TimeSeries{Labels: newLabels, Samples: newSamples})
			continue
		}
		// mergeSamples returns a new allocation — replaces the copied samples above.
		mergedTs[idx].Samples = mergeSamples(mergedTs[idx].Samples, newTs.Samples)
	}

	out := &prompb.ReadResponse{Results: []*prompb.QueryResult{{}}}
	out.Results[0].Timeseries = append(mergedTs, appendTs...)
	return out
}

// copyPrompbResponse deep-copies a ReadResponse (Labels + Samples).
func copyPrompbResponse(src *prompb.ReadResponse) *prompb.ReadResponse {
	if src == nil {
		return &prompb.ReadResponse{Results: []*prompb.QueryResult{{}}}
	}
	dst := &prompb.ReadResponse{Results: make([]*prompb.QueryResult, 0, len(src.Results))}
	for _, r := range src.Results {
		nr := &prompb.QueryResult{Timeseries: make([]*prompb.TimeSeries, 0, len(r.Timeseries))}
		for _, ts := range r.Timeseries {
			newLabels := make([]prompb.Label, len(ts.Labels))
			copy(newLabels, ts.Labels)
			newSamples := make([]prompb.Sample, len(ts.Samples))
			copy(newSamples, ts.Samples)
			nr.Timeseries = append(nr.Timeseries, &prompb.TimeSeries{
				Labels:  newLabels,
				Samples: newSamples,
			})
		}
		dst.Results = append(dst.Results, nr)
	}
	return dst
}

// sizeofPrompbResponse estimates the in-memory size of a ReadResponse.
func sizeofPrompbResponse(r *prompb.ReadResponse) uint64 {
	if r == nil {
		return 0
	}
	var size uintptr
	for _, res := range r.Results {
		size += unsafe.Sizeof(*res)
		for _, ts := range res.Timeseries {
			size += unsafe.Sizeof(*ts)
			size += uintptr(len(ts.Samples) * sampleSize)
			size += uintptr(len(ts.Samples) * samplePtrSize)
			for _, lbl := range ts.Labels {
				size += uintptr(len(lbl.Name) + len(lbl.Value))
				size += unsafe.Sizeof((*string)(unsafe.Pointer(&lbl.Name))) +
					unsafe.Sizeof((*string)(unsafe.Pointer(&lbl.Value)))
			}
		}
	}
	return uint64(size)
}
