package throttler

import (
	"math/rand"
	"time"

	"github.com/metaflowys/metaflow/server/ingester/stream/dbwriter"
)

const (
	THROTTLE_BUCKET = 10 // 由于发送方是有突发的，需要累积一定时间做采样
)

type throttleItem interface {
	Release()
}

type ThrottlingQueue struct {
	flowLogWriter *dbwriter.FlowLogWriter
	index         int

	Throttle        int
	lastFlush       int64
	periodCount     int
	periodEmitCount int

	sampleItems []interface{}
}

func NewThrottlingQueue(throttle int, flowLogWriter *dbwriter.FlowLogWriter, index int) *ThrottlingQueue {
	thq := &ThrottlingQueue{
		Throttle:      throttle * THROTTLE_BUCKET,
		flowLogWriter: flowLogWriter,
		index:         index,
	}
	thq.sampleItems = make([]interface{}, thq.Throttle)
	return thq
}

func (thq *ThrottlingQueue) flush() {
	if thq.periodEmitCount > 0 {
		thq.flowLogWriter.Put(thq.index, thq.sampleItems[:thq.periodEmitCount]...)
	}
}

func (thq *ThrottlingQueue) Send(flow interface{}) bool {
	now := time.Now().Unix()
	if now/THROTTLE_BUCKET != thq.lastFlush/THROTTLE_BUCKET {
		thq.flush()
		thq.lastFlush = now
		thq.periodCount = 0
		thq.periodEmitCount = 0
	}
	if flow == nil {
		return false
	}

	// Reservoir Sampling
	thq.periodCount++
	if thq.periodEmitCount < thq.Throttle {
		thq.sampleItems[thq.periodEmitCount] = flow
		thq.periodEmitCount++
		return true
	} else {
		r := rand.Intn(thq.periodCount)
		if r < thq.Throttle {
			if tItem, ok := thq.sampleItems[r].(throttleItem); ok {
				tItem.Release()
			}
			thq.sampleItems[r] = flow
		} else {
			if tItem, ok := flow.(throttleItem); ok {
				tItem.Release()
			}
		}
		return false
	}
}
