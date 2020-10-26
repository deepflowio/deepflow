package throttler

import (
	"math/rand"
	"sync"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

const (
	THROTTLE_BUCKET = 10 // 由于发送方是有突发的，需要累积一定时间做采样
)

type ThrottlingQueue struct {
	EsQueue queue.QueueWriter
	sync.RWMutex

	Throttle        int
	lastFlush       int64
	periodCount     int
	periodEmitCount int

	sampleItems []interface{}
}

func NewThrottlingQueue(throttle int, esQueue queue.QueueWriter) *ThrottlingQueue {
	thq := &ThrottlingQueue{
		Throttle: throttle * THROTTLE_BUCKET,
		EsQueue:  esQueue,
	}
	thq.sampleItems = make([]interface{}, thq.Throttle)
	return thq
}

func (thq *ThrottlingQueue) flush() {
	if thq.periodEmitCount > 0 {
		thq.EsQueue.Put(thq.sampleItems[:thq.periodEmitCount]...)
	}
}

func (thq *ThrottlingQueue) Send(flow *datatype.TaggedFlow) {
	now := time.Now().Unix()
	thq.Lock()
	if now/THROTTLE_BUCKET != thq.lastFlush/THROTTLE_BUCKET {
		thq.flush()
		thq.lastFlush = now
		thq.periodCount = 0
		thq.periodEmitCount = 0
	}
	if flow == nil {
		thq.Unlock()
		return
	}

	// Reservoir Sampling
	thq.periodCount++
	if thq.periodEmitCount < thq.Throttle {
		thq.sampleItems[thq.periodEmitCount] = flow
		thq.periodEmitCount++
	} else {
		r := rand.Intn(thq.periodCount)
		if r < thq.Throttle {
			thq.sampleItems[r] = flow
		}
	}
	thq.Unlock()
}
