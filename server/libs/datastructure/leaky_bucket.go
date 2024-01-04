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
	"math"
	"time"
)

type LeakyBucket struct {
	rate     uint64
	interval time.Duration // the unit is ms
	token    uint64
	full     uint64
	quantity uint64 // get token number per timer
	timer    *time.Ticker
	multiple uint64 // burst multiple
	running  bool
	spin     SpinLock
}

func (b *LeakyBucket) Init(rate uint64) {
	b.interval = 100
	b.multiple = 10
	// setup timer
	b.timer = time.NewTicker(time.Duration(b.interval) * time.Millisecond)

	// initial token, feed to the bucket full
	b.SetRate(rate)
	b.token = b.full
	b.running = true

	go b.run()
}

func (b *LeakyBucket) Close() {
	b.running = false
	b.timer.Stop()
}

func (b *LeakyBucket) run() {
	for b.running == true {
		<-b.timer.C

		// fill token
		b.spin.Lock()
		if b.token+b.quantity > b.full {
			b.token = b.full
		} else {
			b.token += b.quantity
		}
		b.spin.Unlock()
	}
}

func (b *LeakyBucket) SetRate(rate uint64) {
	if rate == 0 {
		rate = math.MaxUint64
	}
	quantity := rate / uint64(time.Second/time.Millisecond/b.interval)
	if quantity == 0 { // for 1 <= rate < 10
		quantity = 1
	}
	b.spin.Lock()
	b.rate = rate
	b.quantity = quantity
	b.full = b.quantity * b.multiple
	b.spin.Unlock()
}

func (b *LeakyBucket) Acquire(size uint64) bool {
	if b.rate == math.MaxUint64 {
		return true
	}

	b.spin.Lock()
	if b.token < size {
		b.spin.Unlock()
		return false
	}
	b.token -= size
	b.spin.Unlock()
	return true
}
