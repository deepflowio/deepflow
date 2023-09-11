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
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepflowio/deepflow/server/libs/lru"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/statsd"
	"github.com/op/go-logging"
	"github.com/prometheus/prometheus/prompb"
)

var log = logging.MustGetLogger("prometheus.cache")

type CacheItem struct {
	startTime int64 // unit: ms, cache item start time
	endTime   int64 // unit: ms, cache item end time
	data      *common.Result
	rwLock    *sync.RWMutex
}

func (c *CacheItem) Range() int64 {
	return c.endTime - c.startTime
}

func (c *CacheItem) Size() uint64 {
	return unsafeSize(c.data)
}

// it should called under Lock
func (c *CacheItem) replace(d *common.Result) bool {
	new_size := unsafeSize(d)
	if new_size <= config.Cfg.Prometheus.Cache.CacheItemSize {
		// if new_size < max size, replace it
		c.data = d
		return true
	} else {
		// if new_size > max size, mark overflow, do not replace it, delete key
		log.Debugf("case size overflow when replace data, range: [%d-%d], size: %d", c.startTime, c.endTime, new_size)
		return false
	}
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

func (c *CacheItem) Deviation(start int64, end int64) (int64, int64) {
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
		if math.Abs(float64(c.startTime-start)) > config.Cfg.Prometheus.Cache.CacheMaxAllowDeviation {
			return start, end
		} else {
			return start, c.startTime
		}
	}

	// add right data
	if start < c.endTime && start >= c.startTime && end > c.endTime {
		if math.Abs(float64(c.endTime-end)) > config.Cfg.Prometheus.Cache.CacheMaxAllowDeviation {
			return start, end
		} else {
			return c.endTime, end
		}
	}

	return start, end
}

func (c *CacheItem) Data() *common.Result {
	return c.data
}

func (c *CacheItem) MergeCache(start, end int64, cache *common.Result, query *common.Result) (*common.Result, bool) {
	log.Debugf("cache merged, query range: [%d-%d], cache range: [%d-%d]", start, end, c.startTime, c.endTime)
	if query == nil || len(query.Values) == 0 {
		log.Debugf("cache data is nil: %v, query data is nil: %v", cache == nil, query == nil)
		return cache, true
	}

	// re-calculate cache time, because other session may already update cache
	c.rwLock.Lock()
	defer c.rwLock.Unlock()

	if start >= c.startTime && end <= c.endTime {
		// not merge
		log.Debugf("cache full hit, will not merge, cache: [%d-%d], query: [%d-%d]", c.startTime, c.endTime, start, end)
		return cache, true
	}

	// why need to extern left/right here: because other session may already update cache item during sql query
	// so we should re-calculate cache time range here
	// but the `data` merge into cache not completely equals to `data` back to api call

	// extern both side
	if start < c.startTime && end > c.endTime {
		log.Debugf("cache extern both side, cache: [%d-%d], query: [%d-%d]", c.startTime, c.endTime, start, end)
		c.startTime = start
		c.endTime = end
		return query, c.replace(query)
	}

	mergeResult := &common.Result{Columns: query.Columns, Schemas: query.Schemas}
	// extern left
	// cached:   [0, N]
	// replaced: [-X, Y] (0<Y<=N, X<0)
	if end <= c.endTime && end > c.startTime && start < c.startTime {
		if math.Abs(float64(c.startTime-start)) > config.Cfg.Prometheus.Cache.CacheMaxAllowDeviation {
			log.Debugf("cache replace due to deviation too large, cache: [%d-%d], query: [%d-%d]", c.startTime, c.endTime, start, end)
			c.startTime = start
			c.endTime = end
			// in deviation case, will query all data [-X,Y], not only extern data [-X,0]
			// replace cache data with query data
			mergeResult.Values = query.Values
		} else {
			log.Debugf("cache merge extern left, cache: [%d-%d], query: [%d-%d]", c.startTime, c.endTime, start, end)
			c.startTime = start
			// in not deviation case, query data [-X,0], merge into [-X,N]
			// note that `Values` is order by time DESC, so extern `left` should append into right
			mergeResult.Values = append(cache.Values, query.Values...)
		}

		if len(mergeResult.Values) > 0 {
			fv := mergeResult.Values[0].([]interface{})
			lv := mergeResult.Values[len(mergeResult.Values)-1].([]interface{})
			if len(fv) > 0 && len(lv) > 0 {
				log.Debugf("merge result, data range [%v-%v]", lv[0], fv[0])
			}
		}

		return mergeResult, c.replace(mergeResult)
	}

	// extern right
	// cached:   [0, N]
	// replaced: [X,Y] (0<=X<N, Y>N)
	if start < c.endTime && start >= c.startTime && end > c.endTime {
		if math.Abs(float64(c.endTime-end)) > config.Cfg.Prometheus.Cache.CacheMaxAllowDeviation {
			log.Debugf("cache replace due to deviation too large, cache: [%d-%d], query: [%d-%d]", c.startTime, c.endTime, start, end)
			c.startTime = start
			c.endTime = end
			// in deviation case, will query all data [X,Y], not only extern data [N,Y]
			// replace cache data with query data
			mergeResult.Values = query.Values
		} else {
			log.Debugf("cache merge extern right, cache: [%d-%d], query: [%d-%d]", c.startTime, c.endTime, start, end)
			c.endTime = end
			// in not deviation case, query data [N,Y], merge into [0,Y]
			// note that `Values` is order by time DESC, so extern `right` should append into left
			mergeResult.Values = append(query.Values, cache.Values...)
		}

		if len(mergeResult.Values) > 0 {
			fv := mergeResult.Values[0].([]interface{})
			lv := mergeResult.Values[len(mergeResult.Values)-1].([]interface{})
			if len(fv) > 0 && len(lv) > 0 {
				log.Debugf("merge result, data range [%v-%v]", lv[0], fv[0])
			}
		}

		return mergeResult, c.replace(mergeResult)
	}

	return query, true
}

type RemoteReadQueryCache struct {
	cache   *lru.Cache
	counter *CacheCounter
}

var (
	remoteReadQueryCache *RemoteReadQueryCache
	once                 sync.Once
)

func RemoteReadCache() *RemoteReadQueryCache {
	once.Do(func() {
		remoteReadQueryCache = NewRemoteReadQueryCache()
	})
	return remoteReadQueryCache
}

func NewRemoteReadQueryCache() *RemoteReadQueryCache {
	s := &RemoteReadQueryCache{
		cache:   lru.NewCache(config.Cfg.Prometheus.Cache.CacheMaxCount),
		counter: &CacheCounter{Stats: &CacheStats{}},
	}
	statsd.RegisterCountableForIngester("prometheus_cache_counter", s.counter)
	return s
}

func (s *RemoteReadQueryCache) AddOrMerge(req *prompb.ReadRequest, item *CacheItem, cache *common.Result, query *common.Result) *common.Result {
	if req == nil || len(req.Queries) == 0 {
		return cache
	}
	q := req.Queries[0]
	if q.Hints.Func == "series" {
		return query
	}

	key, _ := promRequestToCacheKey(q)
	start, end := GetPromRequestQueryTime(q)
	start = timeAlign(start)
	if item == nil {
		// cache miss
		item = &CacheItem{startTime: start, endTime: end, data: query, rwLock: &sync.RWMutex{}}
		s.cache.Add(key, item)
		return query
	} else {
		// cache hit, merge data
		atomic.AddUint64(&s.counter.Stats.CacheMerge, 1)
		t1 := time.Now()
		result, ok := item.MergeCache(start, end, cache, query)
		d := time.Since(t1)
		atomic.AddUint64(&s.counter.Stats.CacheMergeDuration, uint64(d.Seconds()))
		if !ok {
			// if cache size overflow, means this cache is expired, should delete it
			// maybe 2 ways to resolve: in next query, rewrite cache
			// or add more limitation of cache size
			log.Debugf("case size overflow, cache key: [%s], range: [%d-%d]", key, start, end)
			atomic.AddUint64(&s.counter.Stats.CacheSizeOverFlow, 1)
			s.cache.Remove(key)
		}
		return result
	}
}

func (s *RemoteReadQueryCache) Get(req *prompb.ReadRequest) (*CacheItem, CacheHit, string, int64, int64) {
	if req == nil || len(req.Queries) == 0 {
		return nil, CacheMiss, "", 0, 0
	}
	q := req.Queries[0]
	start, end := GetPromRequestQueryTime(q)
	if q.Hints.Func == "series" {
		// for series api, don't use cache
		// not count cache miss here
		return nil, CacheMiss, "", start, end
	}

	if !config.Cfg.Prometheus.Cache.Enabled {
		return nil, CacheMiss, "", start, end
	}

	// for query api, cache query samples
	key, metric := promRequestToCacheKey(q)
	if strings.Contains(metric, "__") {
		// for DeepFlow Native metrics, don't use cache
		return nil, CacheMiss, metric, start, end
	}

	start = timeAlign(start)
	cacheItem, ok := s.cache.Get(key)
	if !ok {
		atomic.AddUint64(&s.counter.Stats.CacheMiss, 1)
		// totally cache miss, no such key
		return nil, CacheMiss, metric, start, end
	}

	item := cacheItem.(*CacheItem)

	switch item.Hit(start, end) {
	case CacheMiss:
		atomic.AddUint64(&s.counter.Stats.CacheMiss, 1)
		return nil, CacheMiss, metric, start, end
	case CacheHitFull:
		atomic.AddUint64(&s.counter.Stats.CacheHit, 1)
		return item, CacheHitFull, metric, start, end
	case CacheHitPart:
		atomic.AddUint64(&s.counter.Stats.CacheHit, 1)
		query_start, query_end := item.Deviation(start, end)
		return item, CacheHitPart, metric, query_start, query_end
	default:
		return nil, CacheMiss, metric, start, end
	}
}
