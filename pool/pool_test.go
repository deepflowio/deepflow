package pool

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestLockFreePoolSafety(t *testing.T) {
	parallelism := 8
	batchSize := 5000

	got := uint32(0)
	total := uint32(parallelism * batchSize)

	results := make([]uint32, parallelism)

	pool := NewLockFreePool(func() interface{} {
		return uint32(0)
	})

	wg := sync.WaitGroup{}

	wg.Add(parallelism)
	for i := 0; i < parallelism; i++ {
		go func(index int) {
			wg.Done()
			for atomic.LoadUint32(&got) < total {
				e := pool.Get()
				if e == nil {
					t.Error("Concurrency issue!")
					break
				}
				if e.(uint32) == 0 {
					continue
				}
				results[index] += e.(uint32)
				atomic.AddUint32(&got, 1)
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	counter := uint32(0)
	wg.Add(parallelism * 2)
	for i := 0; i < parallelism; i++ {
		go func() {
			for i := 0; i < batchSize; i++ {
				pool.Put(atomic.AddUint32(&counter, 1))
			}
			wg.Done()
		}()
	}
	wg.Wait()

	actual := uint32(0)
	for i := 0; i < parallelism; i++ {
		actual += results[i]
	}
	if expected := (1 + total) * (total) / 2; actual != expected {
		t.Error(actual, expected)
	}
}

func BenchmarkLockFreePoolGet(b *testing.B) {
	pools := make([]LockFreePool, b.N/DEFAULT_POOL_SIZE)
	for i, _ := range pools {
		pool := NewLockFreePool(func() interface{} { return 0 })
		for i := 0; i < DEFAULT_POOL_SIZE; i++ {
			pool.Put(0)
		}
		pools[i] = pool
	}
	b.ResetTimer()
	for i, _ := range pools {
		p := &pools[i]
		for i := 0; i < DEFAULT_POOL_SIZE; i++ {
			p.Get()
		}
	}
}

func BenchmarkLockFreePoolPut(b *testing.B) {
	pools := make([]LockFreePool, b.N/DEFAULT_POOL_SIZE)
	for i, _ := range pools {
		pools[i] = NewLockFreePool(func() interface{} { return 0 })
	}
	b.ResetTimer()
	for i, _ := range pools {
		p := &pools[i]
		for i := 0; i < DEFAULT_POOL_SIZE; i++ {
			p.Put(0)
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
	for i := 0; i < DEFAULT_POOL_SIZE; i++ {
		pool.Put(0)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Put(0)
	}
}
