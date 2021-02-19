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

	totalScan, scanTimes int
}

type DoubleKeyLRUCounter struct {
	Max            int `statsd:"max-bucket"`       // 目前仅统计Get扫描到的最大冲突值
	MaxShortBucket int `statsd:"max-short-bucket"` // 目前仅统计GetByShortKey扫描到的最大冲突值
	Size           int `statsd:"size"`
	MaxLongBucket  int `statsd:"max-long-bucket"` // 目前通过shortKey删除的含有最多的成员数值
	AvgScan        int `statsd:"avg-scan"`        // 平均扫描次数

	totalScan, scanTimes int
}
