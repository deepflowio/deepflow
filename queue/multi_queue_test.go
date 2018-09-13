package queue

import (
	"sync"
	"testing"
)

func TestMultiQueue(t *testing.T) {
	queue := MultiQueue(NewOverwriteQueues("whatever", 17, 1))
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
	if len(queue.(FixedMultiQueue)) != 32 {
		t.Errorf("Expected 32, actually %d", len(queue.(FixedMultiQueue)))
	}
}
