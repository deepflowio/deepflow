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

package dbwriter

import (
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	flowmetricsconfig "github.com/deepflowio/deepflow/server/ingester/flow_metrics/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/app"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
)

var log = logging.MustGetLogger("flow_metrics.dbwriter")

const (
	CACHE_SIZE = 10240
)

type DbWriter struct {
	ckwriters []*ckwriter.CKWriter
}

func NewDbWriter(addrs []string, user, password, clusterName, storagePolicy string, ckWriterCfg config.CKWriterConfig, flowMetricsTtl flowmetricsconfig.FlowMetricsTTL, coldStorages map[string]*ckdb.ColdStorage) (*DbWriter, error) {
	ckwriters := []*ckwriter.CKWriter{}
	tables := zerodoc.GetMetricsTables(ckdb.MergeTree, common.CK_VERSION, clusterName, storagePolicy, flowMetricsTtl.VtapFlow1M, flowMetricsTtl.VtapFlow1S, flowMetricsTtl.VtapApp1M, flowMetricsTtl.VtapApp1S, coldStorages)
	for _, table := range tables {
		counterName := "metrics_1m"
		if table.ID >= uint8(zerodoc.VTAP_FLOW_PORT_1S) && table.ID <= uint8(zerodoc.VTAP_FLOW_EDGE_PORT_1S) {
			counterName = "metrics_1s"
		} else if table.ID >= uint8(zerodoc.VTAP_APP_PORT_1S) && table.ID <= uint8(zerodoc.VTAP_APP_EDGE_PORT_1S) {
			counterName = "app_1s"
		} else if table.ID >= uint8(zerodoc.VTAP_APP_PORT_1M) && table.ID <= uint8(zerodoc.VTAP_APP_EDGE_PORT_1M) {
			counterName = "app_1m"
		}
		ckwriter, err := ckwriter.NewCKWriter(addrs, user, password, counterName, table,
			ckWriterCfg.QueueCount, ckWriterCfg.QueueSize, ckWriterCfg.BatchSize, ckWriterCfg.FlushTimeout)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		ckwriter.Run()
		ckwriters = append(ckwriters, ckwriter)
	}

	return &DbWriter{
		ckwriters: ckwriters,
	}, nil
}

func (w *DbWriter) Put(items ...interface{}) error {
	caches := [zerodoc.VTAP_TABLE_ID_MAX][]interface{}{}
	for i := range caches {
		caches[i] = make([]interface{}, 0, CACHE_SIZE)
	}
	for _, item := range items {
		doc, ok := item.(*app.Document)
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

func (w *DbWriter) Close() {
	for _, ckwriter := range w.ckwriters {
		ckwriter.Close()
	}
}
