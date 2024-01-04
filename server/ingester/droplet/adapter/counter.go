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

package adapter

type PacketCounter struct {
	RxPackets uint64 `statsd:"rx_packets"`
	RxDropped uint64 `statsd:"rx_dropped"` // 当前SEQ减去上次的SEQ
	RxErrors  uint64 `statsd:"rx_errors"`  // 当前SEQ小于上次的SEQ时+1，包乱序并且超出了CACHE_SIZE
	RxInvalid uint64 `statsd:"rx_invalid"` // 错误的包

	TxPackets uint64 `statsd:"tx_packets"`
}

type statsCounter struct {
	counter *PacketCounter
	stats   *PacketCounter
}

func (c *PacketCounter) add(i *PacketCounter) {
	c.RxPackets += i.RxPackets
	c.RxDropped += i.RxDropped
	c.RxErrors += i.RxErrors
	c.RxInvalid += i.RxInvalid
	c.TxPackets += i.TxPackets
}

func (c *statsCounter) init() {
	c.counter = &PacketCounter{}
	c.stats = &PacketCounter{}
}

func (c *statsCounter) GetStatsCounter() interface{} {
	return c.stats
}

func (c *statsCounter) GetCounter() interface{} {
	counter := &PacketCounter{}
	counter, c.counter = c.counter, counter
	return counter
}
