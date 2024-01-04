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

package cache

import (
	"time"

	logging "github.com/op/go-logging"

	. "github.com/deepflowio/deepflow/server/libs/utils"
)

type Instance struct {
	seq          uint64
	maxTimestamp uint32

	cache           []bool
	cacheStartIndex uint64
}

type DropCounter struct {
	Dropped      uint64 `statsd:"dropped"`  // 当前SEQ减去上次的SEQ
	Disorder     uint64 `statsd:"disorder"` // 当前SEQ小于上次的SEQ时+1，包乱序并且超出了CACHE_SIZE
	DisorderSize uint64 `statsd:"disorder_size"`
}

type DropDetection struct {
	name       string
	windowSize uint64

	instances map[uint32]*Instance

	counter *DropCounter
}

var log = logging.MustGetLogger("cache")

func (d *DropDetection) Init(name string, windowSize uint64) {
	d.name = name
	d.windowSize = windowSize
	d.counter = &DropCounter{}
	d.instances = make(map[uint32]*Instance, 2)
}

func (d *DropDetection) GetCounter() interface{} {
	counter := &DropCounter{}
	d.counter, counter = counter, d.counter
	return counter
}

func (d *DropDetection) findAndAdd(id uint32) *Instance {
	var instance *Instance
	if instance = d.instances[id]; instance == nil {
		instance = &Instance{}
		instance.cache = make([]bool, d.windowSize)
		d.instances[id] = instance
	}
	return instance
}

func (d *DropDetection) Detect(id uint32, seq uint64, timestamp uint32) {
	dropped := uint64(0)
	instance := d.findAndAdd(id)

	if instance.seq == 0 || seq == 1 {
		instance.seq = seq
		log.Infof("%s received first packet from %s, with seq %d", d.name, IpFromUint32(uint32(id)), seq)
	}

	if seq < instance.seq {
		if timestamp > instance.maxTimestamp {
			// 序列号更小但时间更大，此时为trident重启，有进程重启告警因此不计算丢包
			log.Infof("%s restart, %s time %s, cache time %s, reset sequence from %d to max(%d-%d, %d)",
				IpFromUint32(uint32(id)), d.name, time.Unix(int64(timestamp), 0), time.Unix(int64(instance.maxTimestamp), 0), instance.seq, seq, d.windowSize, 1)
			for i := range instance.cache {
				instance.cache[i] = false
			}
			instance.cacheStartIndex = 0
			if seq > d.windowSize {
				instance.seq = seq - d.windowSize
			} else {
				instance.seq = 1
			}
		} else {
			if disorderSize := instance.seq - seq; disorderSize > d.counter.DisorderSize {
				d.counter.DisorderSize = disorderSize
			}

			if d.counter.Disorder == 0 {
				// 乱序包，仅检测出后使用日志通知不涉及业务
				log.Infof("%s out of order, %s time %s, cache time %s, packet seq %d, current seq %d",
					IpFromUint32(uint32(id)), time.Unix(int64(timestamp), 0), d.name, time.Unix(int64(instance.maxTimestamp), 0), seq, instance.seq)
			}
			d.counter.Disorder++
			return
		}
	}

	if timestamp > instance.maxTimestamp {
		instance.maxTimestamp = timestamp
	}

	// 尽量flush直至可以cache
	offset := seq - instance.seq
	for i := uint64(0); i < d.windowSize && offset >= d.windowSize; i++ {
		if !instance.cache[instance.cacheStartIndex] {
			dropped++
		}
		instance.cache[instance.cacheStartIndex] = false
		instance.seq++
		instance.cacheStartIndex++
		instance.cacheStartIndex &= d.windowSize - 1
		offset--
	}
	if offset >= d.windowSize { // gap过大，无法并入for循环
		gap := offset - d.windowSize + 1
		instance.seq += gap
		instance.cacheStartIndex += gap
		instance.cacheStartIndex &= d.windowSize - 1
		dropped += uint64(gap)
		offset -= gap
	}

	// 加入cache
	current := (instance.cacheStartIndex + offset) & (d.windowSize - 1)
	instance.cache[current] = true
	for i := current; i != instance.cacheStartIndex; { // 设置尚未到达的包的最坏timestamp
		i = (i - 1) & (d.windowSize - 1)
		if instance.cache[i] {
			break
		}
	}

	// 尽量flush直至有残缺，但只要有残缺就等待，因为向后端传递的数据无需保序
	for i := uint64(0); i < d.windowSize; i++ {
		if instance.cache[instance.cacheStartIndex] { // 可以直接flush
			instance.cache[instance.cacheStartIndex] = false
		} else { // 无法移动窗口
			break
		}

		instance.seq++
		instance.cacheStartIndex++
		instance.cacheStartIndex &= d.windowSize - 1
	}

	// 统计丢包数
	if dropped > 0 {
		// 高负载下Trident或Droplet重启时每个Trident线程会触发windowSize次丢包，使用Debug记录丢包日志避免刷屏
		log.Debugf("%s lost %d packets, packet seq %d, current seq %d", IpFromUint32(uint32(id)), dropped, seq, instance.seq)
	}

	d.counter.Dropped += dropped
}
