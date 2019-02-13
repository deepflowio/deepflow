package datastructure

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestTreiberStackConcurrent(t *testing.T) {
	stack := NewTreiberStack(8192)
	wg := sync.WaitGroup{}

	parallelism := 8
	batchSize := 1000

	got := uint32(0)
	total := uint32(parallelism * batchSize)

	results := make([]uint32, parallelism)

	wg.Add(parallelism)
	for i := 0; i < parallelism; i++ {
		go func(index int) {
			wg.Done()
			for atomic.LoadUint32(&got) < total {
				e := stack.Pop()
				if e == nil {
					continue
				}
				results[index] += e.(uint32)
				atomic.AddUint32(&got, 1)
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	counter := ^uint32(0)
	wg.Add(parallelism * 2)
	for i := 0; i < parallelism; i++ {
		go func() {
			for i := 0; i < batchSize; i++ {
				stack.Push(atomic.AddUint32(&counter, 1))
			}
			wg.Done()
		}()
	}
	wg.Wait()

	actual := uint32(0)
	for i := 0; i < parallelism; i++ {
		actual += results[i]
	}
	if expected := (total - 1) * (total) / 2; actual != expected {
		t.Error(actual, expected)
	}
}
