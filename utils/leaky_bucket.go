package utils

import (
	"sync"
	"time"
)

type LeakyBucket struct {
	sync.Mutex

	last      time.Duration
	rate      uint64
	interval  time.Duration
	available uint64
}

func NewLeakyBucket(rate uint64) LeakyBucket {
	if rate < 1 {
		rate = 1
	}
	interval := time.Second / time.Duration(rate)
	last := time.Duration(time.Now().UnixNano()) - time.Millisecond // for safety
	return LeakyBucket{last: last * interval / interval, rate: rate, interval: interval}
}

func (b *LeakyBucket) Acquire(timestamp time.Duration, size uint64) bool {
	b.available += uint64((timestamp - b.last) / b.interval)
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
