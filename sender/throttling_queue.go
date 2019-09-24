package sender

import (
	"math/rand"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

const (
	_THROTTLE_BUCKET_BITS = 2
	_THROTTLE_BUCKET      = 1 << _THROTTLE_BUCKET_BITS // 2^N。由于发送方是有突发的，需要累积一定时间做采样
)

type ThrottlingQueue struct {
	queue queue.QueueWriter

	throttle        int
	lastFlush       int64
	periodCount     int
	periodEmitCount int

	sampleItems []interface{}
}

func NewThrottlingQueue(throttle int, queue queue.QueueWriter) *ThrottlingQueue {
	thq := &ThrottlingQueue{
		throttle: throttle * _THROTTLE_BUCKET,
		queue:    queue,
	}
	thq.sampleItems = make([]interface{}, thq.throttle)
	return thq
}

func (thq *ThrottlingQueue) flush() {
	thq.queue.Put(thq.sampleItems[:thq.periodEmitCount]...)
}

func (thq *ThrottlingQueue) Send(flow *datatype.TaggedFlow) {
	now := time.Now().Unix()
	if now>>_THROTTLE_BUCKET_BITS != thq.lastFlush>>_THROTTLE_BUCKET_BITS {
		thq.flush()
		thq.lastFlush = now
		thq.periodCount = 0
		thq.periodEmitCount = 0
	}

	// Reservoir Sampling
	thq.periodCount++
	if thq.periodEmitCount < thq.throttle {
		thq.sampleItems[thq.periodEmitCount] = flow
		thq.periodEmitCount++
	} else {
		r := rand.Intn(thq.periodCount)
		if r < thq.throttle {
			datatype.ReleaseTaggedFlow(thq.sampleItems[r].(*datatype.TaggedFlow))
			thq.sampleItems[r] = flow
		} else {
			datatype.ReleaseTaggedFlow(flow)
		}
	}
}
