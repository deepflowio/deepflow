package queue

import (
	"time"

	"gitlab.yunshan.net/yunshan/droplet-libs/stats"
)

const MAX_QUEUE_COUNT = 16

type HashKey = uint8

type Option = interface{}

type OptionRelease = func(x interface{})
type OptionStatsOption = stats.Option
type OptionFlushIndicator = time.Duration // scheduled put nil into queue

type QueueReader interface {
	Get() interface{}
	Gets([]interface{}) int
	Len() int
	Close() error
}

type QueueWriter interface {
	Put(...interface{}) error
	Len() int
	Close() error
}

type MultiQueueReader interface {
	Get(HashKey) interface{}
	Gets(HashKey, []interface{}) int
	Len(HashKey) int
	Close() error
}

type MultiQueueWriter interface {
	Put(HashKey, ...interface{}) error
	Puts([]HashKey, []interface{}) error
	Len(HashKey) int
	Close() error
}
