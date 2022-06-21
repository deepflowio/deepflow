package queue

import (
	"sync"
	"testing"
)

func TestMultiQueue(t *testing.T) {
	queue := NewOverwriteQueues("whatever", 15, 1)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if item := queue.Get(7); item != 10086 {
			t.Errorf("Expected 10086, actually %d", item)
		}
		wg.Done()
	}()
	queue.Put(7, 10086)
	wg.Wait()
	if len(queue) != 16 {
		t.Errorf("Expected 16, actually %d", len(queue))
	}
}
