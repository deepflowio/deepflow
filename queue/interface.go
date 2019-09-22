package queue

import (
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/stats"
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
}

type QueueWriter interface {
	Put(...interface{}) error
	Len() int
}

type MultiQueueReader interface {
	Get(HashKey) interface{}
	Gets(HashKey, []interface{}) int
	Len(HashKey) int
}

type MultiQueueWriter interface {
	Put(HashKey, ...interface{}) error
	Puts([]HashKey, []interface{}) error
	Len(HashKey) int
}
