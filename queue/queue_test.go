package queue

import (
	"sync"
	"testing"
)

func equals(array []interface{}, args ...int) bool {
	if len(array) != len(args) {
		return false
	}
	for i, v := range array {
		if v != args[i] {
			return false
		}
	}
	return true
}

func TestQueue(t *testing.T) {
	queue := NewOverwriteQueue("whatever", 1)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		if item := queue.Get(); item != 10086 {
			t.Errorf("Expected 10086, actually %d", item)
		}
		wg.Done()
	}()
	queue.Put(10086)
	wg.Wait()
}

func TestQueueOverWrite(t *testing.T) {
	queue := NewOverwriteQueue("whatever", 2)
	queue.Put(10086, 10087)
	queue.Put(10088)
	if item := queue.Get(); item != 10087 {
		t.Errorf("Expected 10087, actually %d", item)
	}
}

func TestQueueSize(t *testing.T) {
	queue := NewOverwriteQueue("whatever", 3)
	queue.Put(10086, 10087, 10088, 10089)
	queue.Gets(make([]interface{}, 3))
	if item := queue.Get(); item != 10089 {
		t.Errorf("Expected 10089, actually %d", item)
	}
}

func TestQueueOverSize(t *testing.T) {
	queue := NewOverwriteQueue("whatever", 2)
	queue.Put(10086, 10087)
	queue.Put(10088)
	if item := queue.Get(); item != 10087 {
		t.Errorf("Expected 10087, actually %d", item)
	}
	if item := queue.Get(); item != 10088 {
		t.Errorf("Expected 10088, actually %d", item)
	}
}

func TestQueueGets(t *testing.T) {
	queue := NewOverwriteQueue("whatever", 2)
	queue.Put(10086)
	queue.Put(10087, 10088)
	buffer := make([]interface{}, 2)
	if size := queue.Gets(buffer); size != 2 || !equals(buffer, 10087, 10088) {
		t.Errorf("Expected [10087, 10088], actually %s", buffer)
	}
	queue.Put(10086, 10087)
	buffer = make([]interface{}, 100)
	if size := queue.Gets(buffer); size != 2 || !equals(buffer[:2], 10086, 10087) {
		t.Errorf("Expected [10086, 10087], actually %s", buffer)
	}
}

func TestQueueEmptyGets(t *testing.T) {
	queue := NewOverwriteQueue("whatever", 1)
	queue.Put(10086)
	buffer := make([]interface{}, 0)
	queue.Gets(buffer)
	buffer = make([]interface{}, 1)
	if queue.Gets(buffer); !equals(buffer, 10086) {
		t.Errorf("Expected [10086], actually %s", buffer)
	}
}

func TestQueueTwiceGets(t *testing.T) {
	queue := NewOverwriteQueue("whatever", 5)
	queue.Put(10086, 10087, 10088, 10089, 10090)
	buffer := make([]interface{}, 2)
	if queue.Gets(buffer); !equals(buffer, 10086, 10087) {
		t.Errorf("Expected [10086, 10087], actually %s", buffer)
	}
	buffer = make([]interface{}, 3)
	if queue.Gets(buffer); !equals(buffer, 10088, 10089, 10090) {
		t.Errorf("Expected [10088, 10089, 10090], actually %s", buffer)
	}
}

func TestQueueMultiThread(t *testing.T) {
	queue := NewOverwriteQueue("whatever", 2)
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		if item := queue.Get(); item != 10087 {
			t.Errorf("Expected 10087, actually %s", item)
		}
		wg.Done()
	}()
	go func() {
		for len(queue.waiting) < 1 {
		}
		if item := queue.Get(); item != 10086 {
			t.Errorf("Expected 10086, actually %s", item)
		}
		wg.Done()
	}()
	for len(queue.waiting) < 2 {
	}
	queue.Put(10086, 10087)
	wg.Wait()
	if len(queue.waiting) != 0 {
		t.Error("Should be no waiting")
	}
}

func BenchmarkQueuePut(b *testing.B) {
	queue := NewOverwriteQueue("whatever", 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		queue.Put(i)
	}
}

func BenchmarkQueueGet(b *testing.B) {
	queue := NewOverwriteQueue("whatever", b.N)
	for i := 0; i < b.N; i++ {
		queue.Put(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		queue.Get()
	}
}

func BenchmarkQueueGet8Thread(b *testing.B) {
	queue := NewOverwriteQueue("whatever", b.N)
	for i := 0; i < b.N; i++ {
		queue.Put(i)
	}
	wg := sync.WaitGroup{}
	wg.Add(8)
	b.ResetTimer()
	for t := 0; t < 8; t++ {
		go func() {
			for i := 0; i < b.N/8; i++ {
				queue.Get()
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func BenchmarkQueueGets(b *testing.B) {
	queue := NewOverwriteQueue("whatever", b.N)
	for i := 0; i < b.N; i++ {
		queue.Put(i)
	}
	buffer := make([]interface{}, 4) // buffer太大会导致bench执行过久，虽然性能数据也更好看
	b.ResetTimer()
	for i := 0; i < b.N; i += int(queue.Gets(buffer)) {
	}
}
