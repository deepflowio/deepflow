package pool

import (
	"testing"
)

func BenchmarkPoolGet(b *testing.B) {
	pools := make([]LockFreePool, b.N/1024)
	for i, _ := range pools {
		pool := NewLockFreePool(func() interface{} { return 0 })
		for i := 0; i < 1024; i++ {
			pool.Put(0)
		}
		pools[i] = pool
	}
	b.ResetTimer()
	for i, _ := range pools {
		p := &pools[i]
		for i := 0; i < 1024; i++ {
			p.Get()
		}
	}
}

func BenchmarkPoolPut(b *testing.B) {
	pools := make([]LockFreePool, b.N/1024)
	for i, _ := range pools {
		pools[i] = NewLockFreePool(func() interface{} { return 0 })
	}
	b.ResetTimer()
	for i, _ := range pools {
		p := &pools[i]
		for i := 0; i < 1024; i++ {
			p.Put(0)
		}
	}
}

func BenchmarkPoolHungryGet(b *testing.B) {
	pool := NewLockFreePool(func() interface{} { return 0 })
	for i := 0; i < b.N; i++ {
		pool.Get()
	}
}

func BenchmarkPoolOverPut(b *testing.B) {
	pool := NewLockFreePool(func() interface{} { return 0 })
	for i := 0; i < 1024; i++ {
		pool.Put(0)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Put(0)
	}
}
