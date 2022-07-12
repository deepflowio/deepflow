/*
 * Copyright (c) 2022 Yunshan Networks
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
