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

package throttler

import (
	"math/rand"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/flow_log/dbwriter"
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

	sampleItems    []interface{}
	nonSampleItems []interface{}
}

func NewThrottlingQueue(throttle int, flowLogWriter *dbwriter.FlowLogWriter, index int) *ThrottlingQueue {
	thq := &ThrottlingQueue{
		Throttle:      throttle * THROTTLE_BUCKET,
		flowLogWriter: flowLogWriter,
		index:         index,
	}
	thq.sampleItems = make([]interface{}, thq.Throttle)
	thq.nonSampleItems = make([]interface{}, 0, thq.Throttle)
	return thq
}

func (thq *ThrottlingQueue) flush() {
	if thq.periodEmitCount > 0 {
		thq.flowLogWriter.Put(thq.index, thq.sampleItems[:thq.periodEmitCount]...)
	}
}

func (thq *ThrottlingQueue) SendWithThrottling(flow interface{}) bool {
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

func (thq *ThrottlingQueue) SendWithoutThrottling(flow interface{}) {
	if flow == nil || len(thq.nonSampleItems) >= thq.Throttle {
		if len(thq.nonSampleItems) > 0 {
			thq.flowLogWriter.Put(thq.index, thq.nonSampleItems...)
			thq.nonSampleItems = thq.nonSampleItems[:0]
		}
	}
	if flow != nil {
		thq.nonSampleItems = append(thq.nonSampleItems, flow)
	}
}
