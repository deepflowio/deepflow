package datastructure

import (
	"runtime"
	"sync/atomic"
)

// SpinLock implements a simple atomic spin lock, the zero value for a SpinLock is an unlocked spinlock.
type SpinLock struct {
	f uint32
}

// Lock locks sl. If the lock is already in use, the caller blocks until Unlock is called
func (sl *SpinLock) Lock() {
	for !sl.TryLock() {
		runtime.Gosched() //allow other goroutines to do stuff.
	}
}

// Unlock unlocks sl, unlike [Mutex.Unlock](http://golang.org/pkg/sync/#Mutex.Unlock),
// there's no harm calling it on an unlocked SpinLock
func (sl *SpinLock) Unlock() {
	atomic.StoreUint32(&sl.f, 0)
}

// TryLock will try to lock sl and return whether it succeed or not without blocking.
func (sl *SpinLock) TryLock() bool {
	return atomic.CompareAndSwapUint32(&sl.f, 0, 1)
}

func (sl *SpinLock) String() string {
	if atomic.LoadUint32(&sl.f) == 1 {
		return "Locked"
	}
	return "Unlocked"
}
