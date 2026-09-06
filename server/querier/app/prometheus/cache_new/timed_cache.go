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

	"github.com/deepflowio/deepflow/server/libs/lru"
)

// Status describes the result of a Get call.
type Status int8

const (
	// StatusMissing: no entry exists, or the cached range is disjoint from
	// the query range. A pending placeholder has been inserted. The caller
	// MUST eventually call Complete or Fail to unblock any concurrent waiters.
	StatusMissing Status = iota

	// StatusPending: an entry exists but is still being loaded by another
	// goroutine. Call Lookup.Wait, then call Get again.
	StatusPending

	// StatusPartial: the cache covers part of [start, end]. Lookup.Data holds
	// a deep copy of the cached portion. [QStart, QEnd] is the uncovered
	// sub-range that must be fetched and passed to Complete.
	StatusPartial

	// StatusFull: the cache fully covers [start, end]. Lookup.Data is ready.
	StatusFull
)

// Lookup is the structured result of a TimedCache.Get call.
// It replaces four naked return values with named, typed fields.
type Lookup[T any] struct {
	Status Status
	Data   T     // valid when Status is Full or Partial
	QStart int64 // uncovered sub-range start (relevant for Missing, Pending, Partial)
	QEnd   int64 // uncovered sub-range end

	// ready is closed when the pending load finishes. Never nil.
	ready <-chan struct{}
}

// Wait blocks until the pending load completes or ctx is cancelled.
// Returns true if the load completed, false if ctx expired.
// Only meaningful when Status == StatusPending.
func (l *Lookup[T]) Wait(ctx context.Context) bool {
	select {
	case <-l.ready:
		return true
	case <-ctx.Done():
		return false
	}
}

// Options configures a TimedCache.
type Options[T any] struct {
	MaxCount      int
	MaxItemSize   uint64        // bytes; entries exceeding this are evicted by the cleaner
	CleanInterval time.Duration // how often to run the size-based eviction pass
	AllowTimeGap  int64         // end-time drift (in the same unit as start/end) treated as full hit

	// MergeFn merges newData (covering [ns,ne]) into cached (covering [cs,ce]).
	// Must return a fresh value; must NOT modify either argument in place.
	MergeFn func(cached T, cs, ce int64, newData T, ns, ne int64) T

	// CopyFn returns a deep copy of T so readers get an unaliased value.
	CopyFn func(T) T

	// SizeFn estimates the in-memory footprint of T in bytes.
	SizeFn func(T) uint64
}

// entry is the internal record stored in the LRU.
type entry[T any] struct {
	start, end int64
	data       T

	// filled is set to true by Complete. Until then the entry is a pending
	// placeholder: start/end/data are zero values and must not be read.
	filled bool

	// ready is closed (exactly once, via once) when loading completes.
	// Concurrent waiters select on this channel then retry Get.
	ready chan struct{}
	once  sync.Once
}

func (e *entry[T]) signal() { e.once.Do(func() { close(e.ready) }) }

func newPending[T any]() *entry[T] {
	return &entry[T]{ready: make(chan struct{})}
}

// TimedCache is a time-range LRU cache with merge semantics and a
// pending-placeholder mechanism for concurrent deduplication.
//
// A single Mutex is used for all operations because lru.Cache.Get promotes
// entries (a write to the internal list), making RWMutex semantics incorrect.
type TimedCache[T any] struct {
	mu   sync.Mutex
	lru  *lru.Cache[string, *entry[T]]
	opts Options[T]

	ticker  *time.Ticker
	stop    chan struct{}
	stopOnce sync.Once
}

// NewTimedCache creates a TimedCache and starts the background cleaner goroutine.
func NewTimedCache[T any](opts Options[T]) *TimedCache[T] {
	c := &TimedCache[T]{
		lru:    lru.NewCache[string, *entry[T]](opts.MaxCount),
		opts:   opts,
		stop:   make(chan struct{}),
		ticker: time.NewTicker(opts.CleanInterval),
	}
	go c.cleanLoop()
	return c
}

// Get returns a Lookup describing the cache state for key in [start, end].
//
//   - StatusMissing: a pending placeholder was inserted. Caller MUST call
//     Complete or Fail.
//   - StatusPending: loading in progress. Call Lookup.Wait(ctx), then Get again.
//   - StatusPartial: partial coverage. Fetch [QStart, QEnd] and call Complete.
//   - StatusFull: complete hit. Lookup.Data contains all the data.
func (c *TimedCache[T]) Get(key string, start, end int64) *Lookup[T] {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.lru.Get(key)
	if !ok {
		e = newPending[T]()
		c.lru.Add(key, e)
		return &Lookup[T]{Status: StatusMissing, QStart: start, QEnd: end, ready: e.ready}
	}

	if !e.filled {
		return &Lookup[T]{Status: StatusPending, QStart: start, QEnd: end, ready: e.ready}
	}

	status, qs, qe := c.classify(e, start, end)
	switch status {
	case StatusMissing:
		// disjoint range — replace stale entry with a new pending placeholder
		ne := newPending[T]()
		c.lru.Add(key, ne)
		return &Lookup[T]{Status: StatusMissing, QStart: start, QEnd: end, ready: ne.ready}
	case StatusFull:
		return &Lookup[T]{
			Status: StatusFull,
			Data:   c.opts.CopyFn(e.data),
			QStart: start,
			QEnd:   end,
			ready:  e.ready,
		}
	case StatusPartial:
		return &Lookup[T]{
			Status: StatusPartial,
			Data:   c.opts.CopyFn(e.data),
			QStart: qs,
			QEnd:   qe,
			ready:  e.ready,
		}
	}
	// unreachable; treat as miss
	ne := newPending[T]()
	c.lru.Add(key, ne)
	return &Lookup[T]{Status: StatusMissing, QStart: start, QEnd: end, ready: ne.ready}
}

// classify determines how [qs, qe] overlaps the filled entry e.
// Returns (StatusFull, _, _) when fully covered (including AllowTimeGap slack).
// Returns (StatusPartial, uncoveredStart, uncoveredEnd) for partial overlap.
// Returns (StatusMissing, qs, qe) when completely disjoint.
func (c *TimedCache[T]) classify(e *entry[T], qs, qe int64) (Status, int64, int64) {
	cs, ce := e.start, e.end

	// completely outside — strict inequalities so touching-point queries are hits
	if qe < cs || qs > ce {
		return StatusMissing, qs, qe
	}

	// query extends left only
	if qs < cs && qe <= ce {
		return StatusPartial, qs, cs
	}

	// query extends right only
	if qs >= cs && qe > ce {
		if qe-ce <= c.opts.AllowTimeGap {
			return StatusFull, 0, 0
		}
		return StatusPartial, ce, qe
	}

	// query wider than cache on both sides: treat as partial over the full query range
	if qs < cs && qe > ce {
		return StatusPartial, qs, qe
	}

	// query fully inside cache (or exactly equal, including instant queries start==end)
	return StatusFull, 0, 0
}

// Complete stores or merges data for [start, end] under key.
// Signals any goroutines waiting on a pending placeholder.
// Returns the stored (or merged) data, deep-copied for safe caller use.
func (c *TimedCache[T]) Complete(key string, start, end int64, data T) T {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.lru.Get(key)
	if !ok || !e.filled {
		// first store: either no entry, or the pending placeholder
		if !ok {
			e = newPending[T]()
			c.lru.Add(key, e)
		}
		e.start = start
		e.end = end
		e.data = data
		e.filled = true
		e.signal()
		return c.opts.CopyFn(data)
	}

	merged := c.opts.MergeFn(e.data, e.start, e.end, data, start, end)

	// For disjoint ranges, MergeFn replaces rather than merges, so the range
	// must be set to [start, end] exactly — naive min/max expansion would falsely
	// claim coverage over the gap between the two ranges.
	if end <= e.start || start >= e.end {
		e.start, e.end = start, end
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

// Fail removes a pending (unfilled) placeholder for key and wakes any waiters.
// No-op if the entry has already been filled by Complete.
func (c *TimedCache[T]) Fail(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.lru.Peek(key)
	if !ok || e.filled {
		return
	}
	e.signal() // wake waiters before removing so they can retry with a fresh Get
	c.lru.Remove(key)
}

// Stop shuts down the background cleaner goroutine. Safe to call multiple times.
func (c *TimedCache[T]) Stop() {
	c.stopOnce.Do(func() {
		close(c.stop)
		c.ticker.Stop()
	})
}

func (c *TimedCache[T]) cleanLoop() {
	for {
		select {
		case <-c.ticker.C:
			c.cleanOnce()
		case <-c.stop:
			return
		}
	}
}

// cleanOnce evicts filled entries whose data exceeds MaxItemSize.
//
// The original implementation used a three-phase approach (snapshot outside
// the lock, compute sizes, re-verify under lock) to avoid holding the mutex
// during SizeFn. For a bounded LRU with ≤1024 entries, SizeFn is a trivial
// memory-count loop — holding the lock during the entire scan costs at most
// a few microseconds and eliminates the re-verification complexity entirely.
func (c *TimedCache[T]) cleanOnce() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, k := range c.lru.Keys() {
		e, ok := c.lru.Peek(k)
		if !ok || !e.filled {
			continue
		}
		if c.opts.SizeFn(e.data) > c.opts.MaxItemSize {
			log.Infof("cache evict oversized entry: %s", k)
			c.lru.Remove(k)
		}
	}
}
