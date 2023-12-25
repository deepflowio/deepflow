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

	"github.com/deepflowio/deepflow/server/libs/lru"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/statsd"
	"github.com/prometheus/prometheus/prompb"
)

type CacheItem struct {
	startTime int64 // unit: ms, cache item start time
	endTime   int64 // unit: ms, cache item end time
	data      *prompb.ReadResponse

	rwLock *sync.RWMutex
}

const (
	sampleSize    = int(unsafe.Sizeof(prompb.Sample{}))
	samplePtrSize = int(unsafe.Sizeof(&prompb.Sample{}))
)

func (c *CacheItem) Range() int64 {
	return c.endTime - c.startTime
}

func (c *CacheItem) isZero() bool {
	c.rwLock.RLock()
	defer c.rwLock.RUnlock()

	return c.startTime == 0 && c.endTime == 0
}

func (c *CacheItem) Size() uint64 {
	size := 0
	if c.data == nil {
		return 0
	}
	for i := 0; i < len(c.data.Results); i++ {
		r := c.data.Results[i]
		size += int(unsafe.Sizeof(*r))
		for j := 0; j < len(r.Timeseries); j++ {
			ts := r.Timeseries[j]
			size += int(unsafe.Sizeof(*ts))
			size += len(ts.Samples) * sampleSize
			size += len(ts.Samples) * samplePtrSize
			for k := 0; k < len(ts.Labels); k++ {
				size += int(unsafe.Sizeof(ts.Labels[k]))
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
		return CacheHitPart
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

func getSeriesLabels(lb *[]prompb.Label) string {
	sort.Slice(*lb, func(i, j int) bool { return (*lb)[i].Name < (*lb)[j].Name })
	labels := make([]string, 0, len(*lb))
	for i := 0; i < len(*lb); i++ {
		labels = append(labels, (*lb)[i].Name+":"+(*lb)[i].Value)
	}
	return strings.Join(labels, ",")
}

func (c *CacheItem) mergeResponse(start, end int64, query *prompb.ReadResponse) *prompb.ReadResponse {
	log.Debugf("cache merged, query range: [%d-%d], cache range: [%d-%d]", start, end, c.startTime, c.endTime)
	if query == nil || len(query.Results) == 0 || len(query.Results[0].Timeseries) == 0 {
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
		labels := getSeriesLabels(&ts.Labels)

		for _, existsTs := range cachedTs {
			cachedLabels := getSeriesLabels(&existsTs.Labels)
			if labels == cachedLabels {
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

	lock *sync.RWMutex
}

var (
	readResponseCache *RemoteReadQueryCache
	syncOnce          sync.Once
)

func PromReadResponseCache() *RemoteReadQueryCache {
	syncOnce.Do(func() {
		readResponseCache = NewRemoteReadQueryCache()
	})
	return readResponseCache
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

func (s *RemoteReadQueryCache) AddOrMerge(req *prompb.ReadRequest, query *prompb.ReadResponse) *prompb.ReadResponse {
	if req == nil || len(req.Queries) == 0 {
		return query
	}
	q := req.Queries[0]
	if q.Hints.Func == "series" {
		return query
	}

	key, _ := promRequestToCacheKey(q)
	start, end := GetPromRequestQueryTime(q)
	start = timeAlign(start)

	s.lock.Lock()
	defer s.lock.Unlock()

	item, ok := s.cache.Get(key)
	defer func() {
		if item.Size() > config.Cfg.Prometheus.Cache.CacheItemSize {
			s.cache.Remove(key)
		}
	}()

	if !ok {
		item = &CacheItem{startTime: start, endTime: end, data: query, rwLock: &sync.RWMutex{}}
		s.cache.Add(key, item)
	} else {
		// cache hit, merge data
		atomic.AddUint64(&s.counter.Stats.CacheMerge, 1)
		t1 := time.Now()

		item.rwLock.Lock()
		defer item.rwLock.Unlock()

		item.data = item.mergeResponse(start, end, query)
		d := time.Since(t1)
		atomic.AddUint64(&s.counter.Stats.CacheMergeDuration, uint64(d.Seconds()))
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
			nR.Timeseries = append(nR.Timeseries, &prompb.TimeSeries{
				Labels:  r.Timeseries[j].Labels,
				Samples: r.Timeseries[j].Samples,
			})
		}
		resp.Results = append(resp.Results, nR)
	}

	return resp
}

func (s *RemoteReadQueryCache) Get(req *prompb.ReadRequest) (*prompb.ReadResponse, CacheHit, string, int64, int64) {
	emptyResponse := &prompb.ReadResponse{}
	if req == nil || len(req.Queries) == 0 {
		return emptyResponse, CacheMiss, "", 0, 0
	}
	q := req.Queries[0]
	start, end := GetPromRequestQueryTime(q)
	if q.Hints.Func == "series" {
		// for series api, don't use cache
		// not count cache miss here
		return emptyResponse, CacheMiss, "", start, end
	}

	if !config.Cfg.Prometheus.Cache.RemoteReadCache {
		return emptyResponse, CacheMiss, "", start, end
	}

	// for query api, cache query samples
	key, metric := promRequestToCacheKey(q)
	if strings.Contains(metric, "__") {
		// for DeepFlow Native metrics, don't use cache
		return emptyResponse, CacheMiss, metric, start, end
	}

	start = timeAlign(start)

	// lock for concurrency key reading
	s.lock.Lock()
	defer s.lock.Unlock()
	item, ok := s.cache.Get(key)

	if !ok {
		atomic.AddUint64(&s.counter.Stats.CacheMiss, 1)
		// totally cache miss, no such key
		emptyItem := &CacheItem{startTime: 0, endTime: 0, data: nil, rwLock: &sync.RWMutex{}}
		s.cache.Add(key, emptyItem)
		return emptyResponse, CacheKeyNotFound, metric, start, end
	}

	if item.isZero() {
		return emptyResponse, CacheKeyFoundNil, metric, start, end
	}

	switch item.Hit(start, end) {
	case CacheMiss:
		atomic.AddUint64(&s.counter.Stats.CacheMiss, 1)
		return nil, CacheMiss, metric, start, end
	case CacheHitFull:
		atomic.AddUint64(&s.counter.Stats.CacheHit, 1)
		return item.data, CacheHitFull, metric, start, end
	case CacheHitPart:
		atomic.AddUint64(&s.counter.Stats.CacheHit, 1)
		query_start, query_end := item.FixupQueryTime(start, end)
		return item.data, CacheHitPart, metric, query_start, query_end
	default:
		return emptyResponse, CacheMiss, metric, start, end
	}
}
