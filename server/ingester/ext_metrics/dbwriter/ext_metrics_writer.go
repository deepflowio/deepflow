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
	QUEUE_BATCH_SIZE      = 1024
	EXT_METRICS_DB        = "ext_metrics"
	EXT_METRICS_TABLE     = "metrics"
	DEEPFLOW_SYSTEM_DB    = "deepflow_system"
	DEEPFLOW_SYSTEM_TABLE = "deepflow_system"
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

	tables             map[string]*tableInfo
	metricsWriterCache *ckwriter.CKWriter // the writer for ext_metrics.metrics table
	flowTagWriter      *flow_tag.FlowTagWriter

	counter *Counter
	utils.Closable
}

func (w *ExtMetricsWriter) InitDatabase() error {
	if w.ckdbConn == nil {
		conn, err := common.NewCKConnections(w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword)
		if err != nil {
			return err
		}
		w.ckdbConn = conn
	}
	_, err := w.ckdbConn.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", EXT_METRICS_DB))
	return err
}

func (w *ExtMetricsWriter) getOrCreateCkwriter(s *ExtMetrics) (*ckwriter.CKWriter, error) {
	// fast find
	if s.MsgType != datatype.MESSAGE_TYPE_DFSTATS && w.metricsWriterCache != nil {
		return w.metricsWriterCache, nil
	}

	if info, ok := w.tables[s.TableName()]; ok {
		if info.ckwriter != nil {
			if s.MsgType != datatype.MESSAGE_TYPE_DFSTATS {
				w.metricsWriterCache = info.ckwriter
			}
			return info.ckwriter, nil
		}
	}

	if w.ckdbConn == nil {
		conn, err := common.NewCKConnections(w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword)
		if err != nil {
			return nil, err
		}
		w.ckdbConn = conn
	}

	// 将要创建的表信息
	table := s.GenCKTable(w.ckdbCluster, w.ckdbStoragePolicy, w.ttl, ckdb.GetColdStorage(w.ckdbColdStorages, s.DatabaseName(), s.TableName()))

	ckwriter, err := ckwriter.NewCKWriter(
		w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
		fmt.Sprintf("%s-%s-%d", w.msgType, s.TableName(), w.decoderIndex), w.ckdbTimeZone,
		table, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout)
	if err != nil {
		return nil, err
	}
	// 需要在cluseter其他节点也创建
	if err := w.createTableOnCluster(table); err != nil {
		log.Warningf("crate table on cluster other node failed. %s", err)
	}

	ckwriter.Run()
	if w.ttl != config.DefaultExtMetricsTTL {
		w.setTTL(s.DatabaseName(), s.TableName())
	}

	w.tables[s.TableName()] = &tableInfo{
		tableName: s.TableName(),
		ckwriter:  ckwriter,
	}

	return ckwriter, nil
}

func (w *ExtMetricsWriter) createTableOnCluster(table *ckdb.Table) error {
	// in standalone mode, ckdbWatcher will be nil
	if w.ckdbWatcher == nil {
		return nil
	}
	endpoints, err := w.ckdbWatcher.GetClickhouseEndpointsWithoutMyself()
	if err != nil {
		return err
	}
	for _, endpoint := range endpoints {
		err := ckwriter.InitTable(fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port), w.ckdbUsername, w.ckdbPassword, w.ckdbTimeZone, table)
		if err != nil {
			log.Warningf("node %s:%d init table failed. err: %s", endpoint.Host, endpoint.Port, err)
		} else {
			log.Infof("node %s:%d init table %s success", endpoint.Host, endpoint.Port, table.LocalName)
		}
	}
	return nil
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

func (w *ExtMetricsWriter) setTTL(database, tableName string) error {
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` MODIFY TTL time +  toIntervalHour(%d)",
		database, tableName+ckdb.LOCAL_SUBFFIX, w.ttl)
	log.Info(sql)
	_, err := w.ckdbConn.Exec(sql)
	return err
}

// This function can be called when the FlowTags in the batch are the same (e.g. Prometheus metrics).
func (w *ExtMetricsWriter) WriteBatch(batch []interface{}) {
	if len(batch) == 0 {
		return
	}

	// Only the FlowTag in the first item needs to be written.
	extMetrics := batch[0].(*ExtMetrics)
	ckwriter, err := w.getOrCreateCkwriter(extMetrics)
	if err != nil {
		if w.counter.WriteErr == 0 {
			log.Warningf("get writer failed:", err)
		}
		atomic.AddInt64(&w.counter.WriteErr, 1)
		return
	}
	extMetrics.GenerateNewFlowTags(w.flowTagWriter.Cache)
	w.flowTagWriter.WriteFieldsAndFieldValuesInCache()

	atomic.AddInt64(&w.counter.MetricsCount, int64(len(batch)))
	ckwriter.Put(batch...)
}

func (w *ExtMetricsWriter) Write(m *ExtMetrics) {
	ckwriter, err := w.getOrCreateCkwriter(m)
	if err != nil {
		if w.counter.WriteErr == 0 {
			log.Warningf("get writer failed:", err)
		}
		atomic.AddInt64(&w.counter.WriteErr, 1)
		return
	}
	m.GenerateNewFlowTags(w.flowTagWriter.Cache)
	w.flowTagWriter.WriteFieldsAndFieldValuesInCache()

	atomic.AddInt64(&w.counter.MetricsCount, 1)
	ckwriter.Put(m)
}

func NewExtMetricsWriter(
	decoderIndex int,
	msgType datatype.MessageType,
	db string,
	config *config.Config) (*ExtMetricsWriter, error) {

	ckWriterConfig := config.CKWriterConfig
	// FlowTagWriter
	flowTagWriterConfig := baseconfig.CKWriterConfig{
		QueueCount:   1,                        // Allocate one FlowTagWriter for each ExtMetricsWriter.
		QueueSize:    ckWriterConfig.QueueSize, // Only new FlowTags will be written, so the same QueueSize is used here.
		BatchSize:    ckWriterConfig.BatchSize,
		FlushTimeout: ckWriterConfig.FlushTimeout,
	}
	flowTagWriter, err := flow_tag.NewFlowTagWriter(decoderIndex, msgType.String(), db, config.TTL, DefaultPartition, config.Base, &flowTagWriterConfig)
	if err != nil {
		return nil, err
	}

	// ExtMetricsWriter
	writer := &ExtMetricsWriter{
		decoderIndex:      decoderIndex,
		msgType:           msgType,
		ckdbAddrs:         config.Base.CKDB.ActualAddrs,
		ckdbUsername:      config.Base.CKDBAuth.Username,
		ckdbPassword:      config.Base.CKDBAuth.Password,
		ckdbCluster:       config.Base.CKDB.ClusterName,
		ckdbStoragePolicy: config.Base.CKDB.StoragePolicy,
		ckdbColdStorages:  config.Base.GetCKDBColdStorages(),
		ckdbTimeZone:      config.Base.CKDB.TimeZone,
		tables:            make(map[string]*tableInfo),
		ttl:               config.TTL,
		ckdbWatcher:       config.Base.CKDB.Watcher,
		writerConfig:      ckWriterConfig,
		flowTagWriter:     flowTagWriter,

		counter: &Counter{},
	}
	if err := writer.InitDatabase(); err != nil {
		return nil, err
	}
	common.RegisterCountableForIngester("ext_metrics_writer", writer, stats.OptionStatTags{"msg": msgType.String(), "decoder_index": strconv.Itoa(decoderIndex)})
	return writer, nil
}
