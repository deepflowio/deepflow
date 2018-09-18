package queue

import (
	"sync"
	"testing"

	rawqueue "gitlab.x.lan/yunshan/droplet-libs/queue"
)

func TestMultiQueuePuts(t *testing.T) {
	queue := &MultiQueue{}
	queue.Init("whatever", 8, 3)
	keys := []rawqueue.HashKey{7, 7, 6, 7, 6}
	inBatch := []interface{}{10081, 10082, 10083, 10084, 10085}
	outBatch := make([]interface{}, 8)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if out := queue.Get(4); out != 10081 {
			t.Errorf("Expected 10081, actually %d", out)
		}
		if count := queue.Gets(6, outBatch); count != 2 || outBatch[0] != 10083 || outBatch[1] != 10085 {
			t.Errorf("Expected 2 values: 10083 & 10085, actually %d values: %d & %d", count, outBatch[0], outBatch[1])
		}
		if count := queue.Gets(7, outBatch); count != 2 || outBatch[0] != 10082 || outBatch[1] != 10084 {
			t.Errorf("Expected 2 values: 10082 & 10084, actually %d values: %d & %d", count, outBatch[0], outBatch[1])
		}
		wg.Done()
	}()
	queue.Puts(keys, inBatch)
	wg.Wait()
}
