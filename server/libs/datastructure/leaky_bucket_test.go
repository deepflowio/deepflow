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

package datastructure

import (
	"testing"
	"time"

	"github.com/docker/go-units"
)

func rateTest(rate uint64, t *testing.T) {
	b := LeakyBucket{}
	b.Init(rate)
	interval := 100 * time.Millisecond                        // bucket interval
	if !b.Acquire(10 * rate / uint64(time.Second/interval)) { //burst
		t.Error("Should acquired")
	}
	if b.Acquire(1) {
		t.Error("Should not acquired")
	}
	time.Sleep(interval + interval/2)
	for i := 0; i < 10; i++ {
		if !b.Acquire(rate / 10 / uint64(time.Second/interval)) {
			t.Error("Should acquired")
		}
	}
	if b.Acquire(rate / 10 / uint64(time.Second/interval)) {
		t.Error("Should not acquired")
	}
	b.Close()
}

func TestLeakyBucket(t *testing.T) {
	var rate uint64 = 1000
	rateTest(rate, t)
	rate = 10000000 //10mbps
	rateTest(rate, t)

	rate = 0
	b := LeakyBucket{}
	b.Init(rate)
	for i := 1; i <= 1000; i++ {
		if !b.Acquire(units.GB * 8) {
			t.Error("Should acquired")
		}
	}

}
func BenchmarkLeakyBucket(b *testing.B) {
	b.StopTimer()

	rate := 0
	lb := LeakyBucket{}
	lb.Init(uint64(rate))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		lb.Acquire(1000)
	}
}
func Benchmark4Routines(b *testing.B) {
	b.StopTimer()

	rate := 0
	lb := LeakyBucket{}
	lb.Init(uint64(rate))
	for i := 0; i < 3; i++ {
		go func() {
			for {
				lb.Acquire(1)
			}
		}()
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		lb.Acquire(1)
	}
}
