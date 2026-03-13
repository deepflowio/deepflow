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

// ReadLookup is the result of RemoteReadCache.Get.
// It replaces the previous (*CacheItem, CacheHit, int64, int64) tuple with
// a structured type whose fields have explicit names and semantics.
type ReadLookup struct {
	Status Status
	Data   *prompb.ReadResponse // non-nil when Status is Full or Partial
	QStart int64                // uncovered sub-range (relevant for Missing, Pending, Partial)
	QEnd   int64

	inner *Lookup[*prompb.ReadResponse]
}

// Wait blocks until a pending load completes or ctx is cancelled.
// Only meaningful when Status == StatusPending.
func (r *ReadLookup) Wait(ctx context.Context) bool {
	if r.inner == nil {
		return false
	}
	return r.inner.Wait(ctx)
}

// RemoteReadCache is a time-range cache for raw Prometheus timeseries data.
// It caches *prompb.ReadResponse objects keyed by metric matchers + org/filter
// context, and supports partial time-range hits with sample-level merging.
type RemoteReadCache struct {
	c       *TimedCache[*prompb.ReadResponse]
	counter *CacheCounter
}

var (
	globalReadCache *RemoteReadCache
	globalReadOnce  sync.Once
)

// GlobalReadCache returns the process-wide singleton RemoteReadCache.
func GlobalReadCache() *RemoteReadCache {
	globalReadOnce.Do(func() {
		globalReadCache = NewRemoteReadCache()
	})
	return globalReadCache
}

// NewRemoteReadCache creates a RemoteReadCache configured from Cfg.
func NewRemoteReadCache() *RemoteReadCache {
	cfg := config.Cfg.Prometheus.Cache
	r := &RemoteReadCache{
		counter: newCacheCounter(),
	}
	r.c = NewTimedCache(Options[*prompb.ReadResponse]{
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

// Get checks whether [start, end] is covered by the cache for the given query.
//
// "series" hint queries are never cached (they bypass the cache entirely).
//
// When the returned Status is Missing or Partial, the caller should fetch
// [QStart, QEnd] from the database and pass the result to Complete.
// When the returned Status is Missing, the caller MUST call Complete or Fail
// to unblock any concurrent waiters.
func (r *RemoteReadCache) Get(req *prompb.Query, start, end int64, orgFilter, extraFilters string) *ReadLookup {
	if req.Hints.Func == "series" {
		return &ReadLookup{Status: StatusMissing, QStart: start, QEnd: end}
	}

	key := promRequestToCacheKey(req, orgFilter, extraFilters)
	start = timeAlign(start)

	inner := r.c.Get(key, start, end)

	switch inner.Status {
	case StatusMissing:
		r.counter.miss.Add(1)
	case StatusFull, StatusPartial:
		r.counter.hit.Add(1)
	}

	return &ReadLookup{
		Status: inner.Status,
		Data:   inner.Data,
		QStart: inner.QStart,
		QEnd:   inner.QEnd,
		inner:  inner,
	}
}

// Complete stores or merges resp for the query's time range into the cache.
// Returns a deep copy of the merged result safe to return to callers.
func (r *RemoteReadCache) Complete(req *prompb.ReadRequest, resp *prompb.ReadResponse, orgFilter, extraFilters string) *prompb.ReadResponse {
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

	r.counter.merge.Add(1)
	t0 := time.Now()
	result := r.c.Complete(key, start, end, resp)
	r.counter.mergeDuration.Add(uint64(time.Since(t0).Seconds()))
	return result
}

// Fail removes a pending placeholder on error, waking any waiters.
func (r *RemoteReadCache) Fail(req *prompb.ReadRequest, orgFilter, extraFilter string) {
	if req == nil || len(req.Queries) == 0 {
		return
	}
	key := promRequestToCacheKey(req.Queries[0], orgFilter, extraFilter)
	r.c.Fail(key)
}

// ---------------------------------------------------------------------------
// copy / size helpers
// ---------------------------------------------------------------------------

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

func sizeofPrompbResponse(r *prompb.ReadResponse) uint64 {
	if r == nil {
		return 0
	}
	var size uintptr
	for _, res := range r.Results {
		size += unsafe.Sizeof(*res)
		for _, ts := range res.Timeseries {
			size += unsafe.Sizeof(*ts)
			size += uintptr(len(ts.Samples) * (sampleSize + samplePtrSize))
			for _, lbl := range ts.Labels {
				size += uintptr(len(lbl.Name) + len(lbl.Value))
				// string header overhead
				size += unsafe.Sizeof(lbl.Name) + unsafe.Sizeof(lbl.Value)
			}
		}
	}
	return uint64(size)
}
