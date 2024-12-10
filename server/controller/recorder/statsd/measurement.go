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

package statsd

import (
	"sync/atomic"
)

type Monitor interface {
	Fill(int)
}

type LocalResourceSyncDelay struct {
	Count    uint64 `statsd:"count"`
	AvgDelay uint64 `statsd:"avg_delay"`
	MaxDelay uint64 `statsd:"max_delay"`
	sumDelay uint64
}

func (d *LocalResourceSyncDelay) Fill(delay int) {
	atomic.AddUint64(&d.Count, 1)
	atomic.AddUint64(&d.sumDelay, uint64(delay))
	if atomic.LoadUint64(&d.MaxDelay) < uint64(delay) {
		atomic.StoreUint64(&d.MaxDelay, uint64(delay))
	}
}

type ResourceSyncDelay struct {
	*LocalResourceSyncDelay
}

func newResourceDalay() *ResourceSyncDelay {
	return &ResourceSyncDelay{
		LocalResourceSyncDelay: &LocalResourceSyncDelay{},
	}
}

func (d *ResourceSyncDelay) GetCounter() interface{} {
	local := &LocalResourceSyncDelay{}
	local, d.LocalResourceSyncDelay = d.LocalResourceSyncDelay, local
	if local.Count > 0 {
		local.AvgDelay = local.sumDelay / local.Count
	}
	return local
}

func (r *ResourceSyncDelay) Closed() bool {
	return false
}

type LocalSyncCost struct {
	Cost uint64 `statsd:"cost"`
}

func (c *LocalSyncCost) Fill(cost int) {
	atomic.StoreUint64(&c.Cost, uint64(cost))
	log.Infof("fill cost: %d", cost) // TODO
}

type SyncCost struct {
	*LocalSyncCost
}

func newSyncCost() *SyncCost {
	return &SyncCost{
		LocalSyncCost: &LocalSyncCost{},
	}
}

func (c *SyncCost) GetCounter() interface{} {
	local := &LocalSyncCost{}
	local, c.LocalSyncCost = c.LocalSyncCost, local
	if local.Cost > 0 { // TODO
		log.Infof("local.Cost: %d", local.Cost)
	}
	return local
}

func (c *SyncCost) Closed() bool {
	return false
}
