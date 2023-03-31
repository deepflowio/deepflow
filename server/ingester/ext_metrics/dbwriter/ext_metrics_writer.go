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
	"bytes"
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
	QUEUE_BATCH_SIZE   = 1024
	EXT_METRICS_DB     = "ext_metrics"
	EXT_METRICS_TABLE  = "metrics"
	DEEPFLOW_SYSTEM_DB = "deepflow_system"
)

type ClusterNode struct {
	Addr string
	Port uint16
}

type Counter struct {
	MetricsCount int64 `statsd:"metrics-count"`
	WriteErr     int64 `statsd:"write-err"`

	TableNameCount  int64 `statsd:"table-name-count"`
	FieldNameCount  int64 `statsd:"field-name-count"`
	FieldValueCount int64 `statsd:"field-value-count"`
}

type tableInfo struct {
	tableName string
	ckwriter  *ckwriter.CKWriter
}

type ExtMetricsIdCache struct {
	// lowcard string dictionary
	TableNameIdMap  map[string]uint32
	FieldNameIdMap  map[string]uint32
	FieldValueIdMap map[string]uint32

	// string list
	TableNames  []string
	FieldNames  []string
	FieldValues []string

	// The 32-base expression form of the ID.
	TableNameUids  []string
	FieldNameUids  []string
	FieldValueUids []string

	Buffers []bytes.Buffer
}

func NewExtMetricsIdCache() *ExtMetricsIdCache {
	buffers := []bytes.Buffer{bytes.Buffer{}}
	buffers[0].Grow(1 << 20)

	return &ExtMetricsIdCache{
		TableNameIdMap:  make(map[string]uint32),
		FieldNameIdMap:  make(map[string]uint32),
		FieldValueIdMap: make(map[string]uint32),
		Buffers:         buffers,
	}
}

func (c *ExtMetricsIdCache) GetByteBuffer() *bytes.Buffer {
	buf := &c.Buffers[len(c.Buffers)-1]
	if buf.Len() >= 1<<20-2048 {
		c.Buffers = append(c.Buffers, bytes.Buffer{})
		buf = &c.Buffers[len(c.Buffers)-1]
		buf.Grow(1 << 20)
	}
	return buf
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
	idCache            *ExtMetricsIdCache

	counter *Counter
	utils.Closable
}

func (w *ExtMetricsWriter) LookupTableNameAndId(unsafeTableName string) (string, uint32) {
	c := w.idCache
	tableNameId, exist := c.TableNameIdMap[unsafeTableName]
	if exist {
		return c.TableNames[tableNameId], tableNameId
	} else {
		buf := c.GetByteBuffer()

		// string name
		start := buf.Len()
		buf.WriteString(unsafeTableName)
		tableName := utils.String(buf.Bytes()[start:])

		// int id
		tableNameId = uint32(len(c.TableNameIdMap))

		// string uid
		start = buf.Len()
		buf.WriteString(strconv.FormatUint(uint64(tableNameId), 32) + "z")
		tableNameUid := utils.String(buf.Bytes()[start:])

		c.TableNameIdMap[tableName] = tableNameId
		c.TableNames = append(c.TableNames, tableName)
		c.TableNameUids = append(c.TableNameUids, tableNameUid)
		return tableName, tableNameId
	}
}

func (w *ExtMetricsWriter) LookupFieldNameAndId(unsafeFieldName string) (string, uint32) {
	c := w.idCache
	fieldNameId, exist := c.FieldNameIdMap[unsafeFieldName]
	if exist {
		return c.FieldNames[fieldNameId], fieldNameId
	} else {
		buf := c.GetByteBuffer()

		// string name
		start := buf.Len()
		buf.WriteString(unsafeFieldName)
		fieldName := utils.String(buf.Bytes()[start:])

		// int id
		fieldNameId = uint32(len(c.FieldNameIdMap))

		// string uid
		start = buf.Len()
		buf.WriteString(strconv.FormatUint(uint64(fieldNameId), 32) + "z")
		fieldNameUid := utils.String(buf.Bytes()[start:])

		c.FieldNameIdMap[fieldName] = fieldNameId
		c.FieldNames = append(c.FieldNames, fieldName)
		c.FieldNameUids = append(c.FieldNameUids, fieldNameUid)
		return fieldName, fieldNameId
	}
}

func (w *ExtMetricsWriter) LookupFieldValueAndId(unsafeFieldValue string) (string, uint32) {
	c := w.idCache
	fieldValueId, exist := c.FieldValueIdMap[unsafeFieldValue]
	if exist {
		return c.FieldValues[fieldValueId], fieldValueId
	} else {
		buf := c.GetByteBuffer()

		// string name
		start := buf.Len()
		buf.WriteString(unsafeFieldValue)
		fieldValue := utils.String(buf.Bytes()[start:])

		// int id
		fieldValueId = uint32(len(c.FieldValueIdMap))

		// string uid
		start = buf.Len()
		buf.WriteString(strconv.FormatUint(uint64(fieldValueId), 32) + "z")
		fieldValueUid := utils.String(buf.Bytes()[start:])

		c.FieldValueIdMap[fieldValue] = fieldValueId
		c.FieldValues = append(c.FieldValues, fieldValue)
		c.FieldValueUids = append(c.FieldValueUids, fieldValueUid)
		return fieldValue, fieldValueId
	}
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
	counter.TableNameCount = int64(len(w.idCache.TableNames))
	counter.FieldNameCount = int64(len(w.idCache.FieldNames))
	counter.FieldValueCount = int64(len(w.idCache.FieldValues))
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
	extMetrics.GenerateNewFlowTags(w.flowTagWriter.Cache, w.idCache, true)
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
	m.GenerateNewFlowTags(w.flowTagWriter.Cache, w.idCache, true)
	w.flowTagWriter.WriteFieldsAndFieldValuesInCache()

	atomic.AddInt64(&w.counter.MetricsCount, 1)
	ckwriter.Put(m)
}

func NewExtMetricsWriter(
	decoderIndex int,
	msgType datatype.MessageType,
	db string,
	config *config.Config) (*ExtMetricsWriter, error) {

	// adjust CKWriterConfig
	ckWriterConfig := config.CKWriterConfig
	if msgType == datatype.MESSAGE_TYPE_DFSTATS {
		// FIXME: At present, there are hundreds of tables in the deepflow_system database,
		// and the amount of data is not large. Adjust the queue size to reduce memory consumption.
		// In the future, it is necessary to merge the data tables in deepflow_system with
		// reference to the ext_metrics database.
		ckWriterConfig.QueueCount = 1
		ckWriterConfig.QueueSize >>= 3
		ckWriterConfig.BatchSize >>= 3
	}

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
		idCache:           NewExtMetricsIdCache(),
		counter:           &Counter{},
	}
	if err := writer.InitDatabase(); err != nil {
		return nil, err
	}
	common.RegisterCountableForIngester("ext_metrics_writer", writer, stats.OptionStatTags{"msg": msgType.String(), "decoder_index": strconv.Itoa(decoderIndex)})
	return writer, nil
}
