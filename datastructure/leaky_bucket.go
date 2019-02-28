package datastructure

import (
	"math"
	"sync/atomic"
	"time"
	"unsafe"
)

// 这里的last并非最后一次Acquire的时间，而是最后一次Acquire后，
// 按剩余bucket数量倒推出来的等效时间戳，也就是它不仅包含了时间戳的记录，
// 还包含了剩余bucket数量
type LeakyBucket struct {
	rate     uint64
	interval time.Duration // 生成一次token的间隔
	unit     uint64        // 生成一次token的数量，当interval少于1ns时，unit > 1，否则unit = 1
	last     time.Duration
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
	full := false
	available := uint64((timestamp-b.last)/b.interval) * b.unit
	if available > b.rate {
		available = b.rate
		full = true
	}
	if available >= size {
		available -= size
		if full {
			b.last = timestamp - time.Duration(available/b.unit)*b.interval
		} else {
			b.last += time.Duration(size/b.unit) * b.interval
		}
		return true
	}
	return false
}

func (b *LeakyBucket) SafeAcquire(timestamp time.Duration, size uint64) bool {
	if timestamp < b.last {
		return false
	}
	full := false
	available := uint64((timestamp-b.last)/b.interval) * b.unit
	if available > b.rate {
		available = b.rate
		full = true
	}
	if available >= size {
		available -= size
		if full {
			last := timestamp - time.Duration(available/b.unit)*b.interval
			if atomic.CompareAndSwapUint64((*uint64)(unsafe.Pointer(&b.last)), uint64(b.last), uint64(last)) {
				return true
			}
		}
		atomic.AddUint64((*uint64)(unsafe.Pointer(&b.last)), size/b.unit*uint64(b.interval))
		return true
	}
	return false
}
