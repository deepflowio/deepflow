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

package heap

import (
	"testing"

	"container/heap"
)

func TestBucketHeap(t *testing.T) {
	capacity := 24
	s := NewBucketHeap(24, capacity)

	// 添加0~23并Get
	for i := 0; i < 24; i++ {
		s.Push(0, i)
	}

	// Push所有值bucket=1，并Pop所有bucket=0的值
	for i := 0; i < 24; i++ {
		x := s.Pop()
		if x == nil || x.(int) != 23-i {
			t.Errorf("第 %d 次Pop应该返回最近一次Push的数字 %d，实际返回 %v", i, 23-i, x)
		}

		s.Push(1, i)
	}

	// Push所有值bucket=0，并Pop所有bucket=0的值
	s.Pop()
	for i := 0; i < 24; i++ {
		s.Push(0, i)

		x := s.Pop()
		if x == nil || x.(int) != i {
			t.Errorf("第 %d 次Pop应该返回最近一次Push的数字 %d，实际返回 %v", i, i, x)
		}
	}

	// Push所有值bucket=2，并Pop所有bucket=1的值
	for i := 0; i < 23; i++ {
		s.Push(2, i)

		x := s.Pop()
		if x == nil || x.(int) != 22-i {
			t.Errorf("第 %d 次Pop应该返回最近一次Push的数字 %d，实际返回 %v", i, 22-i, x)
		}
	}

	// 持续Pop直到为空
	x := s.Pop()
	if x == nil || x.(int) != 22 {
		t.Errorf("第 %d 次Pop应该返回最近一次Push的数字 %d，实际返回 %v", 23, 22, x)
	}
	for i := 0; i < 22; i++ {
		x := s.Pop()
		if x == nil || x.(int) != 21-i {
			t.Errorf("第 %d 次Pop应该返回最近一次Push的数字 %d，实际返回 %v", i, 21-i, x)
		}
	}

	// Pop得到nil
	x = s.Pop()
	if x != nil {
		t.Errorf("第 %d 次Pop应该返回nil，实际返回 %v", 23, x)
	}
}

func BenchmarkBucketHeap(b *testing.B) {
	capacity := b.N
	s := NewBucketHeap(24, capacity)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Push(0, i)
	}
	for t := 1; t < 24; t++ {
		for i := 0; i < b.N; i++ {
			x := s.Pop()
			s.Push(t, i)
			if x == nil || x.(int) != b.N-i-1 {
				b.Errorf("t=%d，第 %d 次Pop应该返回最近一次Push的数字 %d，实际返回 %v", t, i, b.N-i-1, x)
			}
		}
	}
	for i := 0; i < b.N; i++ {
		x := s.Pop()
		if x == nil || x.(int) != b.N-i-1 {
			b.Errorf("t=%d，第 %d 次Pop应该返回最近一次Push的数字 %d，实际返回 %v", 24, i, b.N-i-1, x)
		}
	}
}

// An IntHeap is a min-heap of ints.
type intHeap []int

func (h intHeap) Len() int           { return len(h) }
func (h intHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h intHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *intHeap) Push(x interface{}) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(int))
}
func (h *intHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func BenchmarkNativeHeap(b *testing.B) {
	h := make(intHeap, b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h[i] = 0
	}
	heap.Init(&h)
	for t := 1; t < 24; t++ {
		for i := 0; i < b.N; i++ {
			x := heap.Pop(&h)
			heap.Push(&h, t)
			if x == nil || x.(int) != t-1 {
				b.Errorf("t=%d，第 %d 次Pop应该返回最近一次Push的数字 %d，实际返回 %v", t, i, t-1, x)
			}
		}
	}
	for i := 0; i < b.N; i++ {
		x := heap.Pop(&h)
		if x == nil || x.(int) != 23 {
			b.Errorf("t=%d，第 %d 次Pop应该返回最近一次Push的数字 %d，实际返回 %v", 24, i, 23, x)
		}
	}
}
