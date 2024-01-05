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

package throttler

import (
	"math/rand"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/flow_log/dbwriter"
)

const (
	QUEUE_BATCH = 1 << 14
)

type throttleItem interface {
	Release()
}

type ThrottlingQueue struct {
	flowLogWriter *dbwriter.FlowLogWriter
	index         int

	Throttle        int
	throttleBucket  int64 // since the sender has a burst, it needs to accumulate a certain amount of time for sampling
	lastFlush       int64
	periodCount     int
	periodEmitCount int

	sampleItems    []interface{}
	nonSampleItems []interface{}
}

func NewThrottlingQueue(throttle, throttleBucket int, flowLogWriter *dbwriter.FlowLogWriter, index int) *ThrottlingQueue {
	thq := &ThrottlingQueue{
		Throttle:       throttle * throttleBucket,
		throttleBucket: int64(throttleBucket),
		flowLogWriter:  flowLogWriter,
		index:          index,
	}

	if thq.Throttle > 0 {
		thq.sampleItems = make([]interface{}, thq.Throttle)
	}
	thq.nonSampleItems = make([]interface{}, 0, QUEUE_BATCH)
	return thq
}

func (thq *ThrottlingQueue) SampleDisabled() bool {
	return thq.Throttle <= 0
}

func (thq *ThrottlingQueue) flush() {
	if thq.periodEmitCount > 0 {
		if thq.flowLogWriter != nil {
			thq.flowLogWriter.Put(thq.index, thq.sampleItems[:thq.periodEmitCount]...)
		} else {
			for i := range thq.sampleItems[:thq.periodEmitCount] {
				if tItem, ok := thq.sampleItems[i].(throttleItem); ok {
					tItem.Release()
				}
			}
		}
	}
}

func (thq *ThrottlingQueue) SendWithThrottling(flow interface{}) bool {
	if thq.SampleDisabled() {
		thq.SendWithoutThrottling(flow)
		return true
	}

	now := time.Now().Unix()
	if now/thq.throttleBucket != thq.lastFlush/thq.throttleBucket {
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

func (thq *ThrottlingQueue) SendWithoutThrottling(flow interface{}) {
	if flow == nil || len(thq.nonSampleItems) >= QUEUE_BATCH {
		if len(thq.nonSampleItems) > 0 {
			if thq.flowLogWriter != nil {
				thq.flowLogWriter.Put(thq.index, thq.nonSampleItems...)
			} else {
				for i := range thq.nonSampleItems {
					if tItem, ok := thq.nonSampleItems[i].(throttleItem); ok {
						tItem.Release()
					}
				}
			}
			thq.nonSampleItems = thq.nonSampleItems[:0]
		}
	}
	if flow != nil {
		thq.nonSampleItems = append(thq.nonSampleItems, flow)
	}
}
