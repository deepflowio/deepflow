/*
 * Copyright (c) 2022 Yunshan Networks
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

package statsd

import (
	"sync/atomic"
)

type GCounter struct {
	Receive uint64 `statsd:"receive_count"`
	Send    uint64 `statsd:"send_count"`
}

func (c *GCounter) AddReceiveCount(count uint64) {
	atomic.AddUint64(&c.Receive, count)
}

func (c *GCounter) AddSendCount(count uint64) {
	atomic.AddUint64(&c.Send, count)
}

type GPIDCounter struct {
	*GCounter
}

func NewGPIDCounter() *GPIDCounter {
	return &GPIDCounter{
		GCounter: &GCounter{},
	}
}

func (g *GPIDCounter) GetCounter() interface{} {
	counter := &GCounter{}
	counter, g.GCounter = g.GCounter, counter

	return counter
}

func (g *GPIDCounter) Closed() bool {
	return false
}
