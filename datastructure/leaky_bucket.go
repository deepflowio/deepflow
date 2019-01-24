package datastructure

import (
	"math"
	"sync"
	"time"
)

type LeakyBucket struct {
	sync.Mutex

	last      time.Duration
	rate      uint64
	interval  time.Duration
	unit      uint64
	available uint64
}

func (b *LeakyBucket) SetRate(rate uint64) {
	if rate == 0 {
		rate = math.MaxUint64
	}
	interval := time.Duration(uint64(time.Second) / rate)
	b.unit = 1
	if interval < time.Nanosecond {
		interval = time.Nanosecond
		b.unit = rate / uint64(time.Second)
	}
	last := time.Duration(time.Now().UnixNano()) - time.Millisecond // for safety
	b.last = last * interval / interval
	b.rate = rate
	b.interval = interval
}

func (b *LeakyBucket) Acquire(timestamp time.Duration, size uint64) bool {
	if timestamp < b.last {
		return false
	}
	b.available += uint64((timestamp-b.last)/b.interval) * b.unit
	if b.available > b.rate {
		b.available = b.rate
	}
	b.last += (timestamp - b.last) / b.interval * b.interval
	acquirable := b.available >= size
	if acquirable {
		b.available -= size
	}
	return acquirable
}

func (b *LeakyBucket) SafeAcquire(timestamp time.Duration, size uint64) bool {
	b.Lock()
	acquirable := b.Acquire(timestamp, size)
	b.Unlock()
	return acquirable
}
