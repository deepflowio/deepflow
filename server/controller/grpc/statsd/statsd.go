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
	"sync/atomic"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/libs/stats"
)

var log = logging.MustGetLogger("trisolaris/statsd")

type Counter struct {
	ReqCount uint64 `statsd:"req_count"`
	AvgDelay uint64 `statsd:"avg_delay"`
	MaxDelay uint64 `statsd:"max_delay"`
	SumDelay uint64
}

func (c *Counter) AddCostTime(cost uint64) {
	atomic.AddUint64(&c.ReqCount, 1)
	atomic.AddUint64(&c.SumDelay, cost)
	if atomic.LoadUint64(&c.MaxDelay) < cost {
		atomic.StoreUint64(&c.MaxDelay, cost)
	}
}

type GrpcCounter struct {
	*Counter
}

func NewGrpcCounter() *GrpcCounter {
	return &GrpcCounter{
		Counter: &Counter{},
	}
}

func (g *GrpcCounter) GetCounter() interface{} {
	counter := &Counter{}
	counter, g.Counter = g.Counter, counter
	if counter.ReqCount > 0 {
		counter.AvgDelay = counter.SumDelay / counter.ReqCount
	}
	return counter
}

func (g *GrpcCounter) Closed() bool {
	return false
}

type ApiType int

const (
	Sync ApiType = iota
	AnalyzerSync
	Upgrade
	Query
	GetKubernetesClusterID
	GenesisSync
	KubernetesAPISync
	PrometheusAPISync
	GPIDSync
	GetPrometheusLabelIDs
	GetPrometheusTargets
	MaxApiType
)

var ApiTypeToName = map[ApiType]string{
	Sync:                   "Sync",
	AnalyzerSync:           "AnalyzerSync",
	Upgrade:                "Upgrade",
	Query:                  "Query",
	GetKubernetesClusterID: "GetKubernetesClusterID",
	GenesisSync:            "GenesisSync",
	KubernetesAPISync:      "KubernetesAPISync",
	PrometheusAPISync:      "PrometheusAPISync",
	GetPrometheusLabelIDs:  "GetPrometheusLabelIDs",
	GetPrometheusTargets:   "GetPrometheusTargets",
	GPIDSync:               "GPIDSync",
}

var grpcCounters [MaxApiType]*GrpcCounter
var gpidCounter = NewGPIDCounter()

func AddGrpcCostStatsd(apiType ApiType, cost int) {
	if apiType >= MaxApiType {
		return
	}
	counter := grpcCounters[apiType]
	if counter != nil {
		counter.AddCostTime(uint64(cost))
	}
}

func AddGPIDReceiveCounter(count uint64) {
	gpidCounter.AddReceiveCount(count)
}

func AddGPIDSendCounter(count uint64) {
	gpidCounter.AddSendCount(count)
}

func Start() {
	for apiType, name := range ApiTypeToName {
		grpcCounters[apiType] = NewGrpcCounter()
		err := stats.RegisterCountableWithModulePrefix("controller_", "trisolaris", grpcCounters[apiType], stats.OptionStatTags{"grpc_type": name})
		if err != nil {
			log.Error(err)
		}
	}

	err := stats.RegisterCountableWithModulePrefix("controller_", "trisolaris", gpidCounter, stats.OptionStatTags{"grpc_type": "GPIDCount"})
	if err != nil {
		log.Error(err)
	}
	err = stats.RegisterCountableWithModulePrefix("controller_", "trisolaris", GetPrometheusLabelIDsCounterSingleton(), stats.OptionStatTags{"grpc_type": "GetPrometheusLabelIDsDetail"})
	if err != nil {
		log.Error(err)
	}
}
