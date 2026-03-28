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
	"time"

	"github.com/deepflowio/deepflow/server/libs/lru"
)

// entry is an internal cache record for a time-range keyed cache.
type entry[T any] struct {
	start, end int64 // seconds
	data       T

	loaded chan struct{}
	once   sync.Once // ensures loaded is closed exactly once
}

// signal closes the loaded channel exactly once, waking up any waiting goroutines.
func (e *entry[T]) signal() {
	e.once.Do(func() { close(e.loaded) })
}

// TimedCacheOptions configures TimedCache behaviour.
type TimedCacheOptions[T any] struct {
	MaxCount      int
	MaxItemSize   uint64
	CleanInterval time.Duration
	AllowTimeGap  int64 // seconds: tolerated end-time drift treated as full hit

	// MergeFn merges newData (covering [ns,ne]) into cached (covering [cs,ce]).
	// Must not modify its inputs in place; returns the merged result.
	MergeFn func(cached T, cs, ce int64, newData T, ns, ne int64) T

	// CopyFn returns a deep copy of T (for safe reads after the lock is dropped).
	CopyFn func(T) T

	// SizeFn estimates the memory footprint of a cache entry's data.
	SizeFn func(T) uint64
}

// TimedCache is a time-range LRU cache with merge semantics.
// A single Mutex is used throughout: lru.Cache.Get() promotes entries (write
// to internal list), so a plain RWMutex would give no benefit.
type TimedCache[T any] struct {
	mu   sync.Mutex
	lru  *lru.Cache[string, *entry[T]]
	opts TimedCacheOptions[T]

	ticker   *time.Ticker
	stop     chan struct{}
	stopOnce sync.Once
}

// NewTimedCache creates a TimedCache and starts the background cleanup goroutine.
func NewTimedCache[T any](opts TimedCacheOptions[T]) *TimedCache[T] {
	c := &TimedCache[T]{
		lru:    lru.NewCache[string, *entry[T]](opts.MaxCount),
		opts:   opts,
		stop:   make(chan struct{}),
		ticker: time.NewTicker(opts.CleanInterval), // initialize before goroutine to avoid races
	}
	go c.cleanLoop()
	return c
}

// Get checks whether [start,end] is covered by the cached entry for key.
//
// Return values:
//   - CacheKeyNotFound: no entry; a pending placeholder was inserted.
//     Caller MUST eventually call Merge or Remove to unblock waiters.
//   - CachePending (== CacheKeyFoundNil): entry exists but is still loading;
//     wait on the returned entry's loaded channel, then call Get again.
//   - CacheMiss: entry exists but its range is disjoint from [start,end];
//     the placeholder is replaced. Caller MUST call Merge or Remove.
//   - CacheHitPart: partial overlap; queryStart/queryEnd is the missing sub-range.
//   - CacheHitFull: complete hit; entry.data (deep-copied) has all the data.
func (c *TimedCache[T]) Get(key string, start, end int64) (*entry[T], CacheHit, int64, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.lru.Get(key)
	if !ok {
		// insert pending placeholder
		e = &entry[T]{loaded: make(chan struct{})}
		c.lru.Add(key, e)
		return e, CacheKeyNotFound, start, end
	}

	// pending: start==0 && end==0 means data not yet loaded
	if e.start == 0 && e.end == 0 {
		return e, CacheKeyFoundNil, start, end
	}

	hit, qs, qe := c.hitType(e, start, end)
	switch hit {
	case CacheMiss:
		// replace stale entry with a new pending placeholder
		newE := &entry[T]{loaded: make(chan struct{})}
		c.lru.Add(key, newE)
		return newE, CacheMiss, start, end
	case CacheHitFull:
		copied := c.opts.CopyFn(e.data)
		result := &entry[T]{start: e.start, end: e.end, data: copied}
		return result, CacheHitFull, start, end
	case CacheHitPart:
		return e, CacheHitPart, qs, qe
	default:
		return nil, CacheMiss, start, end
	}
}

// hitType determines the cache hit type for a query of [qs,qe] against an entry covering [cs,ce].
// Returns the hit type and the adjusted query start/end for partial hits.
//
// Uses strict inequality for "completely outside" so that zero-width instant
// queries (start==end==cs==ce) are correctly treated as full hits.
func (c *TimedCache[T]) hitType(e *entry[T], qs, qe int64) (CacheHit, int64, int64) {
	cs, ce := e.start, e.end

	// completely outside: strict comparisons so touching-point ranges are not missed
	if qe < cs || qs > ce {
		return CacheMiss, qs, qe
	}

	// query wider than cache on both sides
	if qs < cs && qe > ce {
		return CacheHitPart, qs, qe
	}

	// query extends left
	if qs < cs && qe <= ce {
		return CacheHitPart, qs, cs
	}

	// query extends right
	if qs >= cs && qe > ce {
		if qe-ce <= c.opts.AllowTimeGap {
			return CacheHitFull, 0, 0
		}
		return CacheHitPart, ce, qe
	}

	// query fully inside cache (including start==end==cs==ce for instant queries)
	return CacheHitFull, 0, 0
}

// Merge stores or merges data for [start,end] into the cache entry for key.
// If no non-pending entry exists, stores directly. Signals pending waiters.
// Returns the stored data (deep-copied for safe use by the caller).
func (c *TimedCache[T]) Merge(key string, start, end int64, data T) T {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.lru.Get(key)
	if !ok || (e.start == 0 && e.end == 0) {
		// first store
		if !ok {
			e = &entry[T]{loaded: make(chan struct{})}
			c.lru.Add(key, e)
		}
		e.start = start
		e.end = end
		e.data = data
		e.signal()
		return c.opts.CopyFn(data)
	}

	merged := c.opts.MergeFn(e.data, e.start, e.end, data, start, end)

	// When the new range is disjoint from the cached range, MergeFn performs a
	// replacement (returns newData). The entry must cover exactly [start, end];
	// the naive min/max expansion would falsely imply data for the gap between
	// the two ranges, causing Get to return CacheHitFull for uncached time.
	if end <= e.start || start >= e.end {
		e.start = start
		e.end = end
	} else {
		if start < e.start {
			e.start = start
		}
		if end > e.end {
			e.end = end
		}
	}
	e.data = merged
	e.signal()
	return c.opts.CopyFn(merged)
}

// Remove deletes a pending (zero) entry only. Used to clean up on query error.
func (c *TimedCache[T]) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.lru.Peek(key); ok && e.start == 0 && e.end == 0 {
		c.lru.Remove(key)
	}
}

// Stop shuts down the background cleanup goroutine. Safe to call multiple times.
func (c *TimedCache[T]) Stop() {
	c.stopOnce.Do(func() {
		close(c.stop)
		c.ticker.Stop()
	})
}

func (c *TimedCache[T]) cleanLoop() {
	defer c.ticker.Stop()
	for {
		select {
		case <-c.ticker.C:
			c.cleanOnce()
		case <-c.stop:
			return
		}
	}
}

func (c *TimedCache[T]) cleanOnce() {
	// Step 1: snapshot key→entry pointer atomically in a single lock acquisition.
	c.mu.Lock()
	keys := c.lru.Keys()
	snap := make(map[string]*entry[T], len(keys))
	for _, k := range keys {
		if e, ok := c.lru.Peek(k); ok {
			snap[k] = e
		}
	}
	c.mu.Unlock()

	// Step 2: compute sizes outside the lock (avoids blocking Get/Merge during scan).
	var toRemove []string
	for k, e := range snap {
		if c.opts.SizeFn(e.data) > c.opts.MaxItemSize {
			toRemove = append(toRemove, k)
		}
	}
	if len(toRemove) == 0 {
		return
	}

	// Step 3: re-verify under lock — only remove if the entry pointer is still the
	// same as snapshotted (guards against a new entry replacing the stale one).
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range toRemove {
		if cur, ok := c.lru.Peek(k); ok && cur == snap[k] {
			log.Infof("timed_cache item remove: %s", k)
			c.lru.Remove(k)
		}
	}
}
