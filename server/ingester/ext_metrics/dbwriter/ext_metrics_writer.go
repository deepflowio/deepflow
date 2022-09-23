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
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"

	logging "github.com/op/go-logging"

	"github.com/deepflowys/deepflow/server/ingester/common"
	baseconfig "github.com/deepflowys/deepflow/server/ingester/config"
	"github.com/deepflowys/deepflow/server/ingester/ext_metrics/config"
	"github.com/deepflowys/deepflow/server/ingester/flow_tag"
	"github.com/deepflowys/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowys/deepflow/server/libs/ckdb"
	"github.com/deepflowys/deepflow/server/libs/datatype"
	"github.com/deepflowys/deepflow/server/libs/stats"
	"github.com/deepflowys/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("ext_metrics.dbwriter")

const (
	QUEUE_BATCH_SIZE   = 1024
	EXT_METRICS_DB     = "ext_metrics"
	DEEPFLOW_SYSTEM_DB = "deepflow_system"
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
	msgType      datatype.MessageType
	ckdbAddr     string
	ckdbUsername string
	ckdbPassword string
	ttl          int
	writerConfig baseconfig.CKWriterConfig

	ckdbConn *sql.DB

	createTable   sync.Mutex
	tablesLock    sync.RWMutex
	tables        map[string]*tableInfo
	flowTagWriter *flow_tag.FlowTagWriter

	counter *Counter
	utils.Closable
}

func (w *ExtMetricsWriter) InitDatabase() error {
	if w.ckdbConn == nil {
		conn, err := common.NewCKConnection(w.ckdbAddr, w.ckdbUsername, w.ckdbPassword)
		if err != nil {
			return err
		}
		w.ckdbConn = conn
	}
	_, err := w.ckdbConn.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", EXT_METRICS_DB))
	return err
}

func (w *ExtMetricsWriter) getOrCreateCkwriter(s *ExtMetrics) (*ckwriter.CKWriter, error) {
	w.tablesLock.RLock()
	if info, ok := w.tables[s.TableName]; ok {
		if info.ckwriter != nil {
			w.tablesLock.RUnlock()
			return info.ckwriter, nil
		}
	}
	w.tablesLock.RUnlock()

	w.createTable.Lock()
	defer w.createTable.Unlock()
	if info, ok := w.tables[s.TableName]; ok {
		if info.ckwriter != nil {
			return info.ckwriter, nil
		}
	}

	if w.ckdbConn == nil {
		conn, err := common.NewCKConnection(w.ckdbAddr, w.ckdbUsername, w.ckdbPassword)
		if err != nil {
			return nil, err
		}
		w.ckdbConn = conn
	}

	// 将要创建的表信息
	table := s.GenCKTable(w.ttl)

	ckwriter, err := ckwriter.NewCKWriter(w.ckdbAddr, "", w.ckdbUsername, w.ckdbPassword,
		s.TableName, table, false, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout)
	if err != nil {
		return nil, err
	}
	// 需要在cluseter其他节点也创建
	w.createTableOnCluster(table)

	ckwriter.Run()
	if w.ttl != config.DefaultExtMetricsTTL {
		w.setTTL(s.Database, s.TableName)
	}

	w.tablesLock.Lock()
	w.tables[s.TableName] = &tableInfo{
		tableName: s.TableName,
		ckwriter:  ckwriter,
	}
	w.tablesLock.Unlock()

	return ckwriter, nil
}

func (w *ExtMetricsWriter) createTableOnCluster(table *ckdb.Table) error {
	nodes, err := w.getClusterNodesWithoutLocal(table.Cluster.String())
	if err != nil {
		return err
	}
	for _, node := range nodes {
		err := ckwriter.InitTable(fmt.Sprintf("%s:%d", node.Addr, node.Port), w.ckdbUsername, w.ckdbPassword, table)
		if err != nil {
			log.Warningf("node %s:%d init table failed. err: %s", node.Addr, node.Port, err)
		} else {
			log.Infof("node %s:%d init table %s success", node.Addr, node.Port, table.LocalName)
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
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` MODIFY TTL time +  toIntervalDay(%d)",
		database, tableName+ckdb.LOCAL_SUBFFIX, w.ttl)
	log.Info(sql)
	_, err := w.ckdbConn.Exec(sql)
	return err
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
	atomic.AddInt64(&w.counter.MetricsCount, 1)
	w.flowTagWriter.WriteFieldsAndFieldValues(m.ToFlowTags())
	ckwriter.Put(m)
}

func NewExtMetricsWriter(
	msgType datatype.MessageType,
	db string,
	config *config.Config) (*ExtMetricsWriter, error) {
	// one row of ext_metrics will generate multiple rows of flow_tag, so the writer queue of flow tag needs to be longer.
	flowTagWriterConfig := baseconfig.CKWriterConfig{
		QueueCount:   config.CKWriterConfig.QueueCount,
		QueueSize:    config.CKWriterConfig.QueueSize * 10,
		BatchSize:    config.CKWriterConfig.BatchSize * 10,
		FlushTimeout: config.CKWriterConfig.FlushTimeout,
	}
	flowTagWriter, err := flow_tag.NewFlowTagWriter(msgType.String(), db, config.TTL, DefaultPartition, config.Base, &flowTagWriterConfig)
	if err != nil {
		return nil, err
	}
	writer := &ExtMetricsWriter{
		msgType:       msgType,
		ckdbAddr:      config.Base.CKDB.Primary,
		ckdbUsername:  config.Base.CKDBAuth.Username,
		ckdbPassword:  config.Base.CKDBAuth.Password,
		tables:        make(map[string]*tableInfo),
		ttl:           config.TTL,
		writerConfig:  config.CKWriterConfig,
		flowTagWriter: flowTagWriter,

		counter: &Counter{},
	}
	if err := writer.InitDatabase(); err != nil {
		return nil, err
	}
	common.RegisterCountableForIngester("ext_metrics_writer", writer, stats.OptionStatTags{"msg": msgType.String()})
	return writer, nil
}
