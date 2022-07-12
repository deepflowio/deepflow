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

package pool

import (
	"testing"

	"sync"
)

func BenchmarkNativePoolGetPut1Thread(b *testing.B) {
	pools := make([]*sync.Pool, b.N/1024)
	for p, _ := range pools {
		pool := sync.Pool{New: func() interface{} { return 0 }}
		for i := 0; i < 1024; i++ {
			pool.Put(0)
		}
		pools[p] = &pool
	}

	b.ResetTimer()

	for _, p := range pools {
		for i := 0; i < 1024; i++ {
			p.Get()
		}
	}
}

func BenchmarkNativePoolGetPut2Thread(b *testing.B) {
	pools := make([]*sync.Pool, 16)
	for i := range pools {
		pool := &sync.Pool{New: func() interface{} { return 0 }}
		pools[i] = pool
	}

	put := func(pool []*sync.Pool) {
		for i := 0; i < b.N; i++ {
			for _, p := range pools {
				p.Put(0)
			}
		}
	}

	b.ResetTimer()
	go put(pools)
	for i := 0; i < b.N; i++ {
		for _, p := range pools {
			p.Get()
		}
	}
}

func BenchmarkNativePoolHungryGet(b *testing.B) {
	pool := &sync.Pool{New: func() interface{} { return 0 }}
	for i := 0; i < b.N; i++ {
		pool.Get()
	}
}

func BenchmarkNativePoolOverPut(b *testing.B) {
	pool := &sync.Pool{New: func() interface{} { return 0 }}
	for i := 0; i < 1024; i++ {
		pool.Put(0)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Put(0)
	}
}

func BenchmarkLockFreePoolGetPut1Thread(b *testing.B) {
	pools := make([]*LockFreePool, b.N/1024)
	for p, _ := range pools {
		pool := NewLockFreePool(func() interface{} { return 0 })
		for i := 0; i < 1024; i++ {
			pool.Put(0)
		}
		pools[p] = pool
	}

	b.ResetTimer()

	for _, p := range pools {
		for i := 0; i < 1024; i++ {
			p.Get()
		}
	}
}

func BenchmarkLockFreePoolGetPut2Thread(b *testing.B) {
	pools := make([]*LockFreePool, 16)
	for i := range pools {
		pool := NewLockFreePool(func() interface{} { return 0 })
		pools[i] = pool
	}

	put := func(pool []*LockFreePool) {
		for i := 0; i < b.N; i++ {
			for _, p := range pools {
				p.Put(0)
			}
		}
	}

	b.ResetTimer()
	go put(pools)
	for i := 0; i < b.N; i++ {
		for _, p := range pools {
			p.Get()
		}
	}
}

func BenchmarkLockFreePoolHungryGet(b *testing.B) {
	pool := NewLockFreePool(func() interface{} { return 0 })
	for i := 0; i < b.N; i++ {
		pool.Get()
	}
}

func BenchmarkLockFreePoolOverPut(b *testing.B) {
	pool := NewLockFreePool(func() interface{} { return 0 })
	for i := 0; i < 1024; i++ {
		pool.Put(0)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Put(0)
	}
}
