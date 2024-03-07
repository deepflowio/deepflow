/*
 * Copyright (c) 2023 Yunshan Networks
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
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/deepflowio/deepflow/server/libs/lru"
	"github.com/deepflowio/deepflow/server/querier/app/prometheus/model"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/statsd"
	"github.com/prometheus/prometheus/prompb"
)

type CacheItem struct {
	startTime int64 // unit: s, cache item start time
	endTime   int64 // unit: s, cache item end time
	data      *prompb.ReadResponse

	loadCompleted chan struct{}
	rwLock        *sync.RWMutex
}

const (
	sampleSize    = int(unsafe.Sizeof(prompb.Sample{}))
	samplePtrSize = int(unsafe.Sizeof(&prompb.Sample{}))
)

func (c *CacheItem) Range() int64 {
	return c.endTime - c.startTime
}

func (c *CacheItem) Data() *prompb.ReadResponse {
	return c.data
}

func (c *CacheItem) GetLoadCompleteSignal() chan struct{} {
	return c.loadCompleted
}

func (c *CacheItem) isZero() bool {
	c.rwLock.RLock()
	defer c.rwLock.RUnlock()

	return c.startTime == 0 && c.endTime == 0
}

func (c *CacheItem) Size() uint64 {
	var size uintptr
	if c.data == nil {
		return 0
	}
	for i := 0; i < len(c.data.Results); i++ {
		r := c.data.Results[i]
		size += unsafe.Sizeof(*r)
		for j := 0; j < len(r.Timeseries); j++ {
			ts := r.Timeseries[j]
			size += unsafe.Sizeof(*ts)
			size += uintptr(len(ts.Samples) * sampleSize)
			size += uintptr(len(ts.Samples) * samplePtrSize)
			for k := 0; k < len(ts.Labels); k++ {
				size += uintptr(len(ts.Labels[k].Name) + len(ts.Labels[k].Value))
				size += unsafe.Sizeof((*string)(unsafe.Pointer(&ts.Labels[k].Name))) + unsafe.Sizeof((*string)(unsafe.Pointer(&ts.Labels[k].Value)))
			}
		}
	}
	return uint64(size)
}

func (c *CacheItem) Hit(start int64, end int64) CacheHit {
	c.rwLock.RLock()
	defer c.rwLock.RUnlock()

	// outside cache: cache miss
	if end <= c.startTime || start >= c.endTime {
		return CacheMiss
	}

	// inner cache: cache hit perfectly
	if start >= c.startTime && end <= c.endTime {
		// cache hit
		return CacheHitFull
	}

	// range greater than cache: replace cache
	if start < c.startTime && end > c.endTime {
		return CacheHitPart
	}

	// deviation: fix up start time, cache hit right
	if end <= c.endTime && end > c.startTime && start < c.startTime {
		return CacheHitPart
	}

	// deviation: fix up end time, cache hit left
	if start < c.endTime && start >= c.startTime && end > c.endTime {
		if end-c.endTime <= int64(config.Cfg.Prometheus.Cache.CacheAllowTimeGap) {
			return CacheHitFull
		} else {
			return CacheHitPart
		}
	}
	return CacheMiss
}

func (c *CacheItem) FixupQueryTime(start int64, end int64) (int64, int64) {
	// only cache hit part needs to re-calculate deviation
	c.rwLock.RLock()
	defer c.rwLock.RUnlock()

	// both side out of cache, query all
	if start < c.startTime && end > c.endTime {
		return start, end
	}

	// if the deviation between start & c.start > maxAllowDeviation, directy query all data to replace cache
	// add left data
	if end <= c.endTime && end > c.startTime && start < c.startTime {
		return start, c.startTime
	}

	// add right data
	if start < c.endTime && start >= c.startTime && end > c.endTime {
		return c.endTime, end
	}

	return start, end
}

func (c *CacheItem) mergeResponse(start, end int64, query *prompb.ReadResponse) *prompb.ReadResponse {
	log.Debugf("cache merged, query range: [%d-%d], cache range: [%d-%d]", start, end, c.startTime, c.endTime)
	if query == nil || len(query.Results) == 0 {
		log.Debugf("query data is nil")
		return c.data
	}

	if c.data == nil {
		c.startTime = start
		c.endTime = end
		return query
	}

	// cached: [     ]
	// result:  [   ]
	if start >= c.startTime && end <= c.endTime {
		log.Debugf("cache full hit, will not merge, cache: [%d-%d], query: [%d-%d]", c.startTime, c.endTime, start, end)
		return c.data
	}

	// cached:  [   ]
	// result: [     ]
	if start < c.startTime && end > c.endTime {
		log.Debugf("cache extern both side, cache: [%d-%d], query: [%d-%d]", c.startTime, c.endTime, start, end)
		c.startTime = start
		c.endTime = end
		return query
	}

	// cached: [   ]
	// result:       [   ]

	// cached:       [   ]
	// result: [   ]
	if end <= c.startTime || start >= c.endTime {
		c.startTime = start
		c.endTime = end
		return query
	}

	// only first result contains time series
	queryTs := query.Results[0].Timeseries
	cachedTs := c.data.Results[0].Timeseries

	// cached:   [   ]
	// result: [   ]
	if end <= c.endTime && end > c.startTime && start < c.startTime {
		c.startTime = start
	}
	// cached: [   ]
	// result:   [   ]
	if start < c.endTime && start >= c.startTime && end > c.endTime {
		c.endTime = end
	}

	for _, ts := range queryTs {
		newTsLabelString := getpbLabelString(&ts.Labels, model.CACHE_LABEL_STRING_TAG)
		for _, existsTs := range cachedTs {
			cachedLabelString := getpbLabelString(&existsTs.Labels, model.CACHE_LABEL_STRING_TAG)
			if cachedLabelString == newTsLabelString {
				existsSamples := existsTs.Samples
				existsSamplesStart := existsSamples[0].Timestamp
				existsSamplesEnd := existsSamples[len(existsSamples)-1].Timestamp

				if existsSamplesEnd < ts.Samples[0].Timestamp {
					// cached: [   ]
					// result:       [   ]
					existsTs.Samples = append(existsSamples, ts.Samples...)
				} else if existsSamplesStart > ts.Samples[len(ts.Samples)-1].Timestamp {
					// cached:       [   ]
					// result: [   ]
					existsTs.Samples = append(ts.Samples, existsSamples...)
				} else if existsSamplesEnd >= ts.Samples[0].Timestamp && existsSamplesEnd < ts.Samples[len(ts.Samples)-1].Timestamp {
					// cached: [   ]
					// result:   [   ]
					overlapSample := sort.Search(len(ts.Samples), func(i int) bool {
						return ts.Samples[i].Timestamp > existsSamplesEnd
					})
					existsTs.Samples = append(existsSamples, ts.Samples[overlapSample:]...)
				} else if existsSamplesStart <= ts.Samples[len(ts.Samples)-1].Timestamp && existsSamplesStart > ts.Samples[0].Timestamp {
					// cached:   [   ]
					// result: [   ]
					overlapSample := sort.Search(len(ts.Samples), func(i int) bool {
						return ts.Samples[i].Timestamp >= existsSamplesStart
					})
					existsTs.Samples = append(ts.Samples[:overlapSample], existsSamples...)
				}

				sort.Slice(existsTs.Samples, func(i, j int) bool {
					return existsTs.Samples[i].Timestamp < existsTs.Samples[j].Timestamp
				})
			}
		}

	}

	output := &prompb.ReadResponse{Results: []*prompb.QueryResult{{}}}
	output.Results[0].Timeseries = append(output.Results[0].Timeseries, cachedTs...)

	return output
}

type RemoteReadQueryCache struct {
	cache   *lru.Cache[string, *CacheItem]
	counter *CacheCounter
	// use a ticker to clear oversize cache
	// avoid query -> get cache oversize -> clean -> new query -> ... endless loop
	cleanUpCache *time.Ticker

	lock *sync.RWMutex
}

var (
	readResponseCache *RemoteReadQueryCache
	syncOnce          sync.Once
)

func PromReadResponseCache() *RemoteReadQueryCache {
	syncOnce.Do(func() {
		readResponseCache = NewRemoteReadQueryCache()
		go readResponseCache.startUpCleanCache(config.Cfg.Prometheus.Cache.CacheCleanInterval)
	})
	return readResponseCache
}

func (r *RemoteReadQueryCache) startUpCleanCache(cleanUpInterval int) {
	r.cleanUpCache = time.NewTicker(time.Duration(cleanUpInterval) * time.Second)
	defer func() {
		r.cleanUpCache.Stop()
		if err := recover(); err != nil {
			go r.startUpCleanCache(cleanUpInterval)
		}
	}()
	for range r.cleanUpCache.C {
		r.cleanCache()
	}
}

func (r *RemoteReadQueryCache) cleanCache() {
	keys := r.cache.Keys()
	for _, k := range keys {
		item, ok := r.cache.Peek(k)
		if !ok {
			continue
		}
		size := item.Size()
		if size > config.Cfg.Prometheus.Cache.CacheItemSize {
			log.Infof("cache item remove: %s, real size: %d", k, size)
			r.cache.Remove(k)
		}
	}
}

func NewRemoteReadQueryCache() *RemoteReadQueryCache {
	s := &RemoteReadQueryCache{
		cache:   lru.NewCache[string, *CacheItem](config.Cfg.Prometheus.Cache.CacheMaxCount),
		counter: &CacheCounter{Stats: &CacheStats{}},
		lock:    &sync.RWMutex{},
	}
	statsd.RegisterCountableForIngester("prometheus_cache_counter", s.counter)
	return s
}

func (s *RemoteReadQueryCache) AddOrMerge(req *prompb.ReadRequest, resp *prompb.ReadResponse) *prompb.ReadResponse {
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

	key := promRequestToCacheKey(q)
	start, end := GetPromRequestQueryTime(q)
	start = timeAlign(start)

	s.lock.Lock()
	defer s.lock.Unlock()

	item, ok := s.cache.Get(key)

	// can not clear cache here, because other routine may get data through cache
	if !ok {
		item = &CacheItem{startTime: start, endTime: end, data: resp, rwLock: &sync.RWMutex{}}
		s.cache.Add(key, item)
	} else {
		// cache hit, merge data
		atomic.AddUint64(&s.counter.Stats.CacheMerge, 1)
		t1 := time.Now()

		item.rwLock.Lock()
		defer item.rwLock.Unlock()

		item.data = item.mergeResponse(start, end, resp)
		d := time.Since(t1)
		atomic.AddUint64(&s.counter.Stats.CacheMergeDuration, uint64(d.Seconds()))
	}
	if item.loadCompleted != nil {
		select {
		case _, ok := <-item.loadCompleted:
			log.Debugf("item merged signal close status: %v", ok)
		default:
			// for non-blocking channel get & avoid channel closed panic
			close(item.loadCompleted)
		}
	}
	// avoid pointer ref modify cached data
	return copyResponse(item.data)
}

func copyResponse(cached *prompb.ReadResponse) *prompb.ReadResponse {
	resp := &prompb.ReadResponse{Results: []*prompb.QueryResult{}}
	if cached == nil {
		resp.Results = append(resp.Results, &prompb.QueryResult{})
		return resp
	}

	for i := 0; i < len(cached.Results); i++ {
		r := cached.Results[i]
		nR := &prompb.QueryResult{}
		nR.Timeseries = make([]*prompb.TimeSeries, 0, len(r.Timeseries))
		for j := 0; j < len(r.Timeseries); j++ {
			// remove CACHE_LABEL_STRING_TAG
			// CACHE_LABEL_STRING_TAG mostly appear in last index (len-1)
			// but for robustness should check when cacheLabelIndex<len-1
			cacheLabelIndex := -1
			newLabels := make([]prompb.Label, 0, len(r.Timeseries[j].Labels)-1)
			for k := len(r.Timeseries[j].Labels) - 1; k >= 0; k-- {
				if r.Timeseries[j].Labels[k].Name == model.CACHE_LABEL_STRING_TAG {
					cacheLabelIndex = k
					break
				}
			}
			if cacheLabelIndex > 0 {
				newLabels = append(newLabels, r.Timeseries[j].Labels[:cacheLabelIndex]...)
			}
			if cacheLabelIndex < len(r.Timeseries[j].Labels)-1 {
				newLabels = append(newLabels, r.Timeseries[j].Labels[cacheLabelIndex+1:]...)
			}
			nR.Timeseries = append(nR.Timeseries, &prompb.TimeSeries{
				Labels:  newLabels,
				Samples: r.Timeseries[j].Samples,
			})
		}
		resp.Results = append(resp.Results, nR)
	}

	return resp
}

func (s *RemoteReadQueryCache) Remove(req *prompb.ReadRequest) {
	if req == nil || len(req.Queries) == 0 {
		return
	}
	key := promRequestToCacheKey(req.Queries[0])
	s.lock.Lock()
	defer s.lock.Unlock()

	if item, ok := s.cache.Peek(key); ok && item.isZero() {
		// when item is not zero, means contain other query's data, don't clean up
		s.cache.Remove(key)
	}
}

func (s *RemoteReadQueryCache) Get(req *prompb.Query, start int64, end int64) (*CacheItem, CacheHit, int64, int64) {
	if req.Hints.Func == "series" {
		// for series api, don't use cache
		// not count cache miss here
		return nil, CacheMiss, start, end
	}

	// for query api, cache query samples
	key := promRequestToCacheKey(req)
	start = timeAlign(start)

	// lock for concurrency key reading
	s.lock.Lock()
	defer s.lock.Unlock()
	item, ok := s.cache.Get(key)

	if !ok {
		atomic.AddUint64(&s.counter.Stats.CacheMiss, 1)
		// totally cache miss, no such key
		emptyItem := &CacheItem{startTime: 0, endTime: 0, data: nil, rwLock: &sync.RWMutex{}, loadCompleted: make(chan struct{})}
		s.cache.Add(key, emptyItem)
		return emptyItem, CacheKeyNotFound, start, end
	}

	if item.isZero() {
		return item, CacheKeyFoundNil, start, end
	}

	switch item.Hit(start, end) {
	case CacheMiss:
		atomic.AddUint64(&s.counter.Stats.CacheMiss, 1)
		return nil, CacheMiss, start, end
	case CacheHitFull:
		atomic.AddUint64(&s.counter.Stats.CacheHit, 1)
		return &CacheItem{
			startTime: item.startTime,
			endTime:   item.endTime,
			data:      copyResponse(item.data),
		}, CacheHitFull, start, end
	case CacheHitPart:
		atomic.AddUint64(&s.counter.Stats.CacheHit, 1)
		query_start, query_end := item.FixupQueryTime(start, end)
		return item, CacheHitPart, query_start, query_end
	default:
		return nil, CacheMiss, start, end
	}
}
