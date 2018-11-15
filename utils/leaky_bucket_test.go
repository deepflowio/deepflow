package utils

import (
	"testing"
	"time"
)

func TestLeakyBucket(t *testing.T) {
	timestamp := time.Second
	b := NewLeakyBucket(1000) // 1000 pps, one per 1ms
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
