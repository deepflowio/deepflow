/*
 * Copyright (c) 2024 Yunshan Networks
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

package queue

import (
	"sync"
	"testing"
	"time"
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
	if queue.Len() < 0 {
		t.Errorf("Get len error")
	}
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

func TestReleased(t *testing.T) {
	released := 1
	release := func(x interface{}) {
		released *= x.(int)
	}
	queue := NewOverwriteQueue("whatever", 4, release)
	queue.Put(2, 3, 5, 7)
	queue.Put(11)
	if released != 2 {
		t.Error("Expected 2")
	}
	queue.Put(13, 17) // 11 13 17 7
	released = 1
	queue.Put(19, 23) // 23 13 17 19
	if released != 77 {
		t.Error("Expected 77")
	}
	queue.Put(29, 31) // 23, 29, 31, 19
	released = 1
	queue.Put(37)
	if released != 19 {
		t.Error("Expected 19")
	}
}

func TestPartialRelease(t *testing.T) {
	released := 1
	release := func(x interface{}) {
		released *= x.(int)
	}
	queue := NewOverwriteQueue("whatever", 4, release)
	queue.Put(1, 2, 3)
	queue.Put(5, 7) // 7 .2 3 5
	if released != 1 {
		t.Error("Expected 1, actually", released)
	}
	queue.Get()
	queue.Put(11, 13) // 7 11 13 .5
	if released != 3 {
		t.Error("Expected 3, actually", released)
	}
	queue.Get()
	queue.Get()
	released = 1
	queue.Put(17, 19, 23) // 19 23 .13 17
	if released != 11 {
		t.Error("Expected 11, actually", released)
	}
}

func TestFlushIndicator(t *testing.T) {
	queue := NewOverwriteQueue("whatever", 1, time.Microsecond)
	queue.Get()
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
