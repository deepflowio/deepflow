package utils

import (
	"testing"
	"time"

	"github.com/docker/go-units"
)

func TestLeakyBucket(t *testing.T) {
	timestamp := time.Second
	b := LeakyBucket{}
	b.SetRate(1000) // 1000 pps, one per 1ms
	b.last = timestamp
	if b.Acquire(timestamp, 1) {
		t.Error("Should not acquired")
	}
	timestamp += time.Millisecond
	if !b.Acquire(timestamp, 1) {
		t.Error("Should acquired")
	}
	timestamp += time.Millisecond - time.Microsecond
	if b.Acquire(timestamp, 1) {
		t.Error("Should not acquired")
	}
	timestamp += time.Microsecond * 2
	if !b.Acquire(timestamp, 1) {
		t.Error("Should acquired")
	}
	timestamp += time.Millisecond * 2
	if !b.Acquire(timestamp, 1) {
		t.Error("Should acquired")
	}
	if !b.Acquire(timestamp, 1) {
		t.Error("Should acquired")
	}
	timestamp = 2 * time.Second
	if b.Acquire(timestamp, 1000) {
		t.Error("Should not acquired")
	}
	if !b.Acquire(timestamp, 1000-6) {
		t.Error("Should acquired")
	}
	timestamp = 4 * time.Second
	if b.Acquire(timestamp, 2000) {
		t.Error("Should not acquired")
	}
	if !b.Acquire(timestamp, 1000) {
		t.Error("Should acquired")
	}
}

func TestLeakyBucketBps(t *testing.T) {
	b := LeakyBucket{}
	b.SetRate(units.TB * 8) // 100Tbps
	b.last = time.Second
	for i := 1; i <= 1000; i++ {
		if !b.Acquire(time.Second+time.Millisecond*time.Duration(i), units.GB*8) {
			t.Error("Should acquired")
		}
	}
}
