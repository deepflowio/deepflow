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

package lru

import (
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("lru")

const (
	_BLOCK_SIZE_BITS = 8
	_BLOCK_SIZE      = 1 << _BLOCK_SIZE_BITS
	_BLOCK_SIZE_MASK = _BLOCK_SIZE - 1
)

func minPowerOfTwo(v int) (int, int) {
	for i := 0; i < 30; i++ {
		if v <= 1<<uint64(i) {
			return 1 << uint64(i), i
		}
	}
	return 1, 0
}

type Counter struct {
	Max     int `statsd:"max-bucket"` // 统计Get扫描到的最大值
	Size    int `statsd:"size"`
	AvgScan int `statsd:"avg-scan"` // 平均扫描次数
	Hit     int `statsd:"hit"`
	Miss    int `statsd:"miss"`

	totalScan, scanTimes int
}

type DoubleKeyLRUCounter struct {
	Max            int `statsd:"max-bucket"`       // 目前仅统计Get扫描到的最大冲突值
	MaxShortBucket int `statsd:"max-short-bucket"` // 目前仅统计GetByShortKey扫描到的最大冲突值
	Size           int `statsd:"size"`
	MaxLongBucket  int `statsd:"max-long-bucket"` // 目前通过shortKey删除的含有最多的成员数值
	AvgScan        int `statsd:"avg-scan"`        // 平均扫描次数
	Hit            int `statsd:"hit"`
	Miss           int `statsd:"miss"`

	totalScan, scanTimes int
}
