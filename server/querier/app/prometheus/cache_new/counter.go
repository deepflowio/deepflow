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
	"sync/atomic"
)

// CacheStats holds cache telemetry counters with statsd tags.
type CacheStats struct {
	CacheSizeOverFlow  uint64 `statsd:"cache_size_overflow"`
	CacheMiss          uint64 `statsd:"cache_miss"`
	CacheHit           uint64 `statsd:"cache_hit"`
	CacheMerge         uint64 `statsd:"cache_merge"`
	CacheMergeDuration uint64 `statsd:"cache_merge_duration"`
}

// CacheCounter satisfies the statsd.Countable interface.
// Each field is an atomic.Uint64 so callers can increment without holding a lock.
// GetCounter atomically swaps in a fresh CacheStats and returns the old one,
// which is correct because the swap itself is atomic (pointer-width on all supported arches).
type CacheCounter struct {
	miss          atomic.Uint64
	hit           atomic.Uint64
	merge         atomic.Uint64
	mergeDuration atomic.Uint64
	sizeOverflow  atomic.Uint64

	stats atomic.Pointer[CacheStats]
	exited bool
}

func newCacheCounter() *CacheCounter {
	c := &CacheCounter{}
	c.stats.Store(new(CacheStats))
	return c
}

// GetCounter drains all counters into a CacheStats snapshot and resets them.
// Called periodically by the statsd reporter.
func (c *CacheCounter) GetCounter() interface{} {
	return &CacheStats{
		CacheMiss:          c.miss.Swap(0),
		CacheHit:           c.hit.Swap(0),
		CacheMerge:         c.merge.Swap(0),
		CacheMergeDuration: c.mergeDuration.Swap(0),
		CacheSizeOverFlow:  c.sizeOverflow.Swap(0),
	}
}

func (c *CacheCounter) Close()  { c.exited = true }
func (c *CacheCounter) Closed() bool { return c.exited }
