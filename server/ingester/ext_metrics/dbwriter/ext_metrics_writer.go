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
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/common"
	baseconfig "github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/ext_metrics/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_tag"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("ext_metrics.dbwriter")

const (
	QUEUE_BATCH_SIZE             = 1024
	EXT_METRICS_DB               = "ext_metrics"
	EXT_METRICS_TABLE            = "metrics"
	DEEPFLOW_SYSTEM_DB           = "deepflow_system"
	DEEPFLOW_SYSTEM_SERVER_TABLE = "deepflow_system_server"
	DEEPFLOW_SYSTEM_AGENT_TABLE  = "deepflow_system_agent"
)

type ClusterNode struct {
	Addr string
	Port uint16
}

type Counter struct {
	MetricsCount int64 `statsd:"metrics-count"`
	WriteErr     int64 `statsd:"write-err"`
}

type tableInfo struct {
	tableName string
	ckwriter  *ckwriter.CKWriter
}

type ExtMetricsWriter struct {
	decoderIndex      int
	msgType           datatype.MessageType
	ckdbAddrs         []string
	ckdbUsername      string
	ckdbPassword      string
	ckdbCluster       string
	ckdbStoragePolicy string
	ckdbColdStorages  map[string]*ckdb.ColdStorage
	ckdbTimeZone      string
	ttl               int
	writerConfig      baseconfig.CKWriterConfig
	ckdbWatcher       *baseconfig.Watcher

	ckdbConn common.DBs

	flowTagWriter *flow_tag.FlowTagWriter
	ckWriter      *ckwriter.CKWriter

	counter *Counter
	utils.Closable
}

func (w *ExtMetricsWriter) getClusterNodesWithoutLocal(clusterName string) ([]ClusterNode, error) {
	sql := fmt.Sprintf("SELECT host_address,port,is_local FROM system.clusters WHERE cluster='%s'", clusterName)
	log.Info(sql)
	rows, err := w.ckdbConn.Query(sql)
	if err != nil {
		w.ckdbConn = nil
		return nil, err
	}
	var addr string
	var port uint16
	var isLocal uint8
	var clusterNodes = []ClusterNode{}
	for rows.Next() {
		err := rows.Scan(&addr, &port, &isLocal)
		if err != nil {
			return nil, err
		}
		if isLocal != 1 {
			clusterNodes = append(clusterNodes, ClusterNode{addr, port})
		}
	}
	return clusterNodes, nil
}

func (w *ExtMetricsWriter) GetCounter() interface{} {
	var counter *Counter
	counter, w.counter = w.counter, &Counter{}
	return counter
}

// This function can be called when the FlowTags in the batch are the same (e.g. Prometheus metrics).
func (w *ExtMetricsWriter) WriteBatch(batch []interface{}) {
	if len(batch) == 0 {
		return
	}

	// Only the FlowTag in the first item needs to be written.
	extMetrics := batch[0].(*ExtMetrics)
	extMetrics.GenerateNewFlowTags(w.flowTagWriter.Cache)
	w.flowTagWriter.WriteFieldsAndFieldValuesInCache()

	atomic.AddInt64(&w.counter.MetricsCount, int64(len(batch)))
	w.ckWriter.Put(batch...)
}

func (w *ExtMetricsWriter) Write(m *ExtMetrics) {
	m.GenerateNewFlowTags(w.flowTagWriter.Cache)
	w.flowTagWriter.WriteFieldsAndFieldValuesInCache()

	atomic.AddInt64(&w.counter.MetricsCount, 1)
	w.ckWriter.Put(m)
}

func NewExtMetricsWriter(
	decoderIndex int,
	msgType datatype.MessageType,
	flowTagTablePrefix string,
	config *config.Config) (*ExtMetricsWriter, error) {

	ckWriterConfig := config.CKWriterConfig
	// FlowTagWriter
	flowTagWriterConfig := baseconfig.CKWriterConfig{
		QueueCount:   1,                        // Allocate one FlowTagWriter for each ExtMetricsWriter.
		QueueSize:    ckWriterConfig.QueueSize, // Only new FlowTags will be written, so the same QueueSize is used here.
		BatchSize:    ckWriterConfig.BatchSize,
		FlushTimeout: ckWriterConfig.FlushTimeout,
	}
	flowTagWriter, err := flow_tag.NewFlowTagWriter(decoderIndex, msgType.String(), flowTagTablePrefix, config.TTL, ckdb.TimeFuncTwelveHour, config.Base, &flowTagWriterConfig)
	if err != nil {
		return nil, err
	}

	// ExtMetricsWriter
	w := &ExtMetricsWriter{
		decoderIndex:      decoderIndex,
		msgType:           msgType,
		ckdbAddrs:         config.Base.CKDB.ActualAddrs,
		ckdbUsername:      config.Base.CKDBAuth.Username,
		ckdbPassword:      config.Base.CKDBAuth.Password,
		ckdbCluster:       config.Base.CKDB.ClusterName,
		ckdbStoragePolicy: config.Base.CKDB.StoragePolicy,
		ckdbColdStorages:  config.Base.GetCKDBColdStorages(),
		ckdbTimeZone:      config.Base.CKDB.TimeZone,
		ttl:               config.TTL,
		ckdbWatcher:       config.Base.CKDB.Watcher,
		writerConfig:      ckWriterConfig,
		flowTagWriter:     flowTagWriter,

		counter: &Counter{},
	}

	s := AcquireExtMetrics()
	s.Timestamp = uint32(time.Now().Unix())
	s.MsgType = msgType
	table := s.GenCKTable(w.ckdbCluster, w.ckdbStoragePolicy, w.ttl, ckdb.GetColdStorage(w.ckdbColdStorages, s.DatabaseName(), s.TableName()))
	ckwriter, err := ckwriter.NewCKWriter(
		w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
		fmt.Sprintf("%s-%s-%d", w.msgType, s.TableName(), w.decoderIndex), w.ckdbTimeZone,
		table, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout, w.ckdbWatcher)
	if err != nil {
		return nil, err
	}

	w.ckWriter = ckwriter
	w.ckWriter.Run()

	common.RegisterCountableForIngester("ext_metrics_writer", w, stats.OptionStatTags{"msg": msgType.String(), "decoder_index": strconv.Itoa(decoderIndex)})
	return w, nil
}
