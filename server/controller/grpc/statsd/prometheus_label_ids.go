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

package statsd

import (
	"sync"
	"sync/atomic"
)

var (
	gplidCounterOnce sync.Once
	gplidCounter     *GetPrometheusLabelIDsCounter
)

func GetPrometheusLabelIDsCounterSingleton() *GetPrometheusLabelIDsCounter {
	gplidCounterOnce.Do(func() {
		gplidCounter = &GetPrometheusLabelIDsCounter{
			PrometheusLabelIDsCounter: &PrometheusLabelIDsCounter{},
		}
	})
	return gplidCounter
}

type GetPrometheusLabelIDsCounter struct {
	*PrometheusLabelIDsCounter
}

func NewGetPrometheusLabelIDsCounter() *GetPrometheusLabelIDsCounter {
	return &GetPrometheusLabelIDsCounter{
		PrometheusLabelIDsCounter: NewPrometheusLabelIDsCounter(),
	}
}

func (g *GetPrometheusLabelIDsCounter) GetCounter() interface{} {
	counter := &PrometheusLabelIDsCounter{}
	counter, g.PrometheusLabelIDsCounter = g.PrometheusLabelIDsCounter, counter
	return counter
}

func (g *GetPrometheusLabelIDsCounter) Closed() bool {
	return false
}

type PrometheusLabelIDsCounter struct {
	ReceiveMetricCount uint64 `statsd:"receive_metric_count"`
	ReceiveLabelCount  uint64 `statsd:"receive_label_count"`
	ReceiveTargetCount uint64 `statsd:"receive_target_count"`
	SendMetricCount    uint64 `statsd:"send_metric_count"`
	SendLabelCount     uint64 `statsd:"send_label_count"`
	SendTargetCount    uint64 `statsd:"send_target_count"`
}

func NewPrometheusLabelIDsCounter() *PrometheusLabelIDsCounter {
	return &PrometheusLabelIDsCounter{}
}

func (c *PrometheusLabelIDsCounter) Fill(pc *PrometheusLabelIDsCounter) {
	atomic.AddUint64(&c.ReceiveMetricCount, pc.ReceiveMetricCount)
	atomic.AddUint64(&c.ReceiveLabelCount, pc.ReceiveLabelCount)
	atomic.AddUint64(&c.ReceiveTargetCount, pc.ReceiveTargetCount)
	atomic.AddUint64(&c.SendMetricCount, pc.SendMetricCount)
	atomic.AddUint64(&c.SendLabelCount, pc.SendLabelCount)
	atomic.AddUint64(&c.SendTargetCount, pc.SendTargetCount)
}
