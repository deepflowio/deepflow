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

package dbwriter

import (
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	flowmetricsconfig "github.com/deepflowio/deepflow/server/ingester/flow_metrics/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/app"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	flow_metrics "github.com/deepflowio/deepflow/server/libs/flow-metrics"
)

var log = logging.MustGetLogger("flow_metrics.dbwriter")

const (
	CACHE_SIZE       = 10240
	QUEUE_BATCH_SIZE = 1024

	metricsFilterApp = "app"
)

// DbWriter 指标数据写入的接口定义
type DbWriter interface {
	Put(items ...interface{}) error
	Close()
}

type CkDbWriter struct {
	ckwriters []*ckwriter.CKWriter
}

func NewCkDbWriter(addrs []string, user, password, clusterName, storagePolicy, timeZone string, ckWriterCfg config.CKWriterConfig, flowMetricsTtl flowmetricsconfig.FlowMetricsTTL, coldStorages map[string]*ckdb.ColdStorage, ckdbWatcher *config.Watcher) (DbWriter, error) {
	ckwriters := []*ckwriter.CKWriter{}
	tables := flow_metrics.GetMetricsTables(ckdb.MergeTree, common.CK_VERSION, clusterName, storagePolicy, flowMetricsTtl.VtapFlow1M, flowMetricsTtl.VtapFlow1S, flowMetricsTtl.VtapApp1M, flowMetricsTtl.VtapApp1S, coldStorages)
	for _, table := range tables {
		counterName := "metrics_1m"
		if table.ID >= uint8(flow_metrics.NETWORK_1S) && table.ID <= uint8(flow_metrics.NETWORK_MAP_1S) {
			counterName = "metrics_1s"
		} else if table.ID >= uint8(flow_metrics.APPLICATION_1S) && table.ID <= uint8(flow_metrics.APPLICATION_MAP_1S) {
			counterName = "app_1s"
		} else if table.ID >= uint8(flow_metrics.APPLICATION_1M) && table.ID <= uint8(flow_metrics.APPLICATION_MAP_1M) {
			counterName = "app_1m"
		}
		ckwriter, err := ckwriter.NewCKWriter(addrs, user, password, counterName, timeZone, table,
			ckWriterCfg.QueueCount, ckWriterCfg.QueueSize, ckWriterCfg.BatchSize, ckWriterCfg.FlushTimeout, ckdbWatcher)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		ckwriter.Run()
		ckwriters = append(ckwriters, ckwriter)
	}

	return &CkDbWriter{
		ckwriters: ckwriters,
	}, nil
}

func (w *CkDbWriter) Put(items ...interface{}) error {
	caches := [flow_metrics.METRICS_TABLE_ID_MAX][]interface{}{}
	for i := range caches {
		caches[i] = make([]interface{}, 0, CACHE_SIZE)
	}
	for _, item := range items {
		doc, ok := item.(app.Document)
		if !ok {
			log.Warningf("receive wrong type data %v", item)
			continue
		}
		id, err := doc.TableID()
		if err != nil {
			log.Warningf("doc table id not found. %v", doc)
			continue
		}
		caches[id] = append(caches[id], doc)
	}

	for i, cache := range caches {
		if len(cache) > 0 {
			w.ckwriters[i].Put(cache...)
		}
	}
	return nil
}

func (w *CkDbWriter) Close() {
	for _, ckwriter := range w.ckwriters {
		ckwriter.Close()
	}
}
