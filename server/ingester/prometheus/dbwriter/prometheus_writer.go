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
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/common"
	baseconfig "github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_tag"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/config"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype/prompb"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("prometheus.dbwriter")

const (
	QUEUE_BATCH_SIZE = 1024
	PROMETHEUS_DB    = "prometheus"
	PROMETHEUS_TABLE = "samples"
)

type ClusterNode struct {
	Addr string
	Port uint16
}

type Counter struct {
	MetricsCount int64 `statsd:"metrics-count"`
	WriteErr     int64 `statsd:"write-err"`
}

type PrometheusCKWriter struct {
	ckwriter             *ckwriter.CKWriter
	updateAppLabelColumn bool
}

// all 'PrometheusWriters' share 'prometheusCKWriters' to write to ClickHouse, preventing each PrometheusWriter from creating CKWriter and causing excessive resource consumption
type PrometheusCKWriters struct {
	writers [MAX_APP_LABEL_COLUMN_INDEX + 1]PrometheusCKWriter
	sync.Mutex
}

var prometheusCKWriters PrometheusCKWriters

func getPrometheusCKWriter(columnCount int) *PrometheusCKWriter {
	return &prometheusCKWriters.writers[columnCount]
}

func setPrometheusCKWriter(columnCount int, w *ckwriter.CKWriter) {
	prometheusCKWriters.writers[columnCount] = PrometheusCKWriter{ckwriter: w}
}

func (p PrometheusCKWriters) EndpointsChange(addrs []string) {
	log.Infof("prometheus clickhouse endpoints changes to %+v", addrs)
	for i := range prometheusCKWriters.writers {
		prometheusCKWriters.writers[i].updateAppLabelColumn = true
	}
}

func lockPrometheusCKWriters() {
	prometheusCKWriters.Lock()
}

func unlockPrometheusCKWriters() {
	prometheusCKWriters.Unlock()
}

type PrometheusWriter struct {
	decoderIndex      int
	name              string
	ckdbAddrs         *[]string
	currentCkdbAddrs  []string
	ckdbUsername      string
	ckdbPassword      string
	ckdbCluster       string
	ckdbStoragePolicy string
	ckdbType          string
	ckdbColdStorages  map[string]*ckdb.ColdStorage
	ckdbTimeZone      string
	ttl               int
	writerConfig      baseconfig.CKWriterConfig
	ckdbWatcher       *baseconfig.Watcher

	ckdbConn common.DBs

	appLabelColumnIncrement int
	metricsWriterCache      *ckwriter.CKWriter // the writer for prometheus.metrics table
	flowTagWriter           *flow_tag.FlowTagWriter
	systemColumnsTableName  string

	counter *Counter
	utils.Closable
}

func (w *PrometheusWriter) InitTable(appLabelCount int) error {
	if w.ckdbConn == nil {
		conn, err := common.NewCKConnections(w.currentCkdbAddrs, w.ckdbUsername, w.ckdbPassword)
		if err != nil {
			return err
		}
		w.ckdbConn = conn
	}
	_, err := w.ckdbConn.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", PROMETHEUS_DB))

	w.getOrCreateCkwriter(&PrometheusSample{PrometheusSampleMini: PrometheusSampleMini{AppLabelValueIDs: make([]uint32, appLabelCount+1)}})
	return err
}

func (w *PrometheusWriter) updateAppLabelValueIdColumns(orgID uint16, appLabelCount int) error {
	log.Infof("organization %d needs to update the number of app_label_value_id column in the prometheus table to %d", orgID, appLabelCount)
	orgDatabase := ckdb.OrgDatabasePrefix(orgID) + PROMETHEUS_DB
	currentCount, err := w.getCurrentAppLabelColumnCount(orgDatabase)
	if err != nil {
		return err
	}
	// the prometheus.samples table has not been created yet, so there is no need to update the columns.
	if currentCount == 0 {
		return nil
	}
	maxLabelColumnIndex, err := w.getMaxAppLabelColumnIndex(orgDatabase)
	if err != nil {
		log.Warning(err)
	}

	if currentCount != maxLabelColumnIndex {
		log.Infof("current app label count (%d) smaller than max app label index (%d)", currentCount, maxLabelColumnIndex)
		currentCount = 0
	}

	if currentCount < appLabelCount {
		startIndex, endIndex := currentCount+1, appLabelCount
		if err := w.addAppLabelColumns(w.ckdbConn, startIndex, endIndex, orgDatabase); err != nil {
			return err
		}
		// 需要在cluseter其他节点也增加列
		if err := w.addAppLabelColumnsOnCluster(startIndex, endIndex, orgDatabase); err != nil {
			log.Warningf("other node failed when add app_value_id columns which index from %d to %d: %s", startIndex, endIndex, err)
		}
	}
	return nil
}

func (w *PrometheusWriter) getOrCreateCkwriter(s PrometheusSampleInterface) (*ckwriter.CKWriter, error) {
	// AppLabelValueIDs[0] is target label
	if s.AppLabelLen() == 0 {
		return nil, fmt.Errorf("AppLabelValueIDs is empty")
	}
	appLabelCount := s.AppLabelLen() - 1
	if appLabelCount > MAX_APP_LABEL_COLUMN_INDEX {
		return nil, fmt.Errorf("the length of AppLabelValueIDs(%d) is > MAX_APP_LABEL_COLUMN_INDEX(%d)", s.AppLabelLen(), MAX_APP_LABEL_COLUMN_INDEX)
	}
	writer := getPrometheusCKWriter(appLabelCount)
	if writer.ckwriter != nil && !writer.updateAppLabelColumn {
		return writer.ckwriter, nil
	}
	lockPrometheusCKWriters()
	defer unlockPrometheusCKWriters()
	// check again
	writer = getPrometheusCKWriter(appLabelCount)
	if writer.ckwriter != nil && !writer.updateAppLabelColumn {
		return writer.ckwriter, nil
	}

	if w.ckdbConn == nil || !reflect.DeepEqual(w.currentCkdbAddrs, *w.ckdbAddrs) {
		w.currentCkdbAddrs = utils.CloneStringSlice(*w.ckdbAddrs)
		if w.ckdbConn != nil {
			w.ckdbConn.Close()
			log.Infof("prometheus clickhouse endpoints change from %+v to %+v", w.currentCkdbAddrs, *w.ckdbAddrs)
		}
		conn, err := common.NewCKConnections(w.currentCkdbAddrs, w.ckdbUsername, w.ckdbPassword)
		if err != nil {
			return nil, err
		}
		w.ckdbConn = conn
	}

	if err := w.updateAppLabelValueIdColumns(s.OrgID(), appLabelCount); err != nil {
		return nil, err
	}
	writer.updateAppLabelColumn = false

	if writer.ckwriter != nil {
		return writer.ckwriter, nil
	}

	startTime := time.Now()
	log.Infof("start create new ckwriter for prometheus, app label count: %d", appLabelCount)
	// 将要创建的表信息
	table := s.GenCKTable(w.ckdbCluster, w.ckdbStoragePolicy, w.ckdbType, w.ttl, ckdb.GetColdStorage(w.ckdbColdStorages, s.DatabaseName(), s.TableName()), appLabelCount)

	ckwriter, err := ckwriter.NewCKWriter(
		w.currentCkdbAddrs, w.ckdbUsername, w.ckdbPassword,
		fmt.Sprintf("%s-%s-%d-%d", w.name, s.TableName(), w.decoderIndex, appLabelCount), w.ckdbTimeZone,
		table, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout, w.ckdbWatcher)
	if err != nil {
		return nil, err
	}

	ckwriter.Run()
	setPrometheusCKWriter(appLabelCount, ckwriter)
	log.Infof("finish create new ckwriter for prometheus, app label count: %d, cost time: %s", appLabelCount, time.Since(startTime))

	return ckwriter, nil
}

func (w *PrometheusWriter) addAppLabelColumnsOnCluster(startIndex, endIndex int, orgDatabase string) error {
	// in standalone mode, ckdbWatcher will be nil
	if w.ckdbWatcher == nil {
		return nil
	}
	endpoints, err := w.ckdbWatcher.GetClickhouseEndpointsWithoutMyself()
	if err != nil {
		return err
	}

	ckdbAddrs := []string{}
	for _, endpoint := range endpoints {
		ckdbAddrs = append(ckdbAddrs, net.JoinHostPort(endpoint.Host, fmt.Sprintf("%d", endpoint.Port)))
	}
	conn, err := common.NewCKConnections(ckdbAddrs, w.ckdbUsername, w.ckdbPassword)
	if err != nil {
		return err
	}
	defer conn.Close()
	return w.addAppLabelColumns(conn, startIndex, endIndex, orgDatabase)
}

func (w *PrometheusWriter) addAppLabelColumns(conn common.DBs, startIndex, endIndex int, orgDatabase string) error {
	prometheusTables := []string{PROMETHEUS_TABLE, PROMETHEUS_TABLE + ckdb.LOCAL_SUBFFIX}
	if w.ckdbType == ckdb.CKDBTypeByconity {
		prometheusTables = []string{PROMETHEUS_TABLE}
	}
	for i := startIndex; i <= endIndex; i++ {
		for _, table := range prometheusTables {
			_, err := conn.ExecParallel(fmt.Sprintf("ALTER TABLE %s.`%s` ADD COLUMN app_label_value_id_%d %s",
				orgDatabase, table, i, ckdb.UInt32))
			if err != nil {
				if strings.Contains(err.Error(), "column with this name already exists") {
					log.Infof("db: %s, table: %s error: %s", orgDatabase, table, err)
				} else {
					return err
				}
			}
		}
	}
	return nil
}

func (w *PrometheusWriter) getCurrentAppLabelColumnCount(orgDatabase string) (int, error) {
	sql := fmt.Sprintf("SELECT count(0) FROM system.%s where database='%s' and table='%s' and name like '%%app_label_value%%'", w.systemColumnsTableName, orgDatabase, PROMETHEUS_TABLE)
	log.Info(sql)
	rows, err := w.ckdbConn.Query(sql)
	if err != nil {
		w.ckdbConn = nil
		return 0, err
	}
	var count, minCount int
	for i := range rows {
		for rows[i].Next() {
			err := rows[i].Scan(&count)
			if err != nil {
				return 0, err
			}
			if minCount == 0 || minCount > count {
				minCount = count
			}
		}
	}
	return minCount, nil
}

func (w *PrometheusWriter) getMaxAppLabelColumnIndex(orgDatabase string) (int, error) {
	var name, maxName string
	sql := fmt.Sprintf("WITH (SELECT max(length(name)) FROM system.%s where database='%s' and  table='%s' and name like '%%app_label_value%%') as maxNameLength SELECT max(name) from system.%s where database='%s' and  table='%s' and name like '%%app_label_value%%' and length(name)=maxNameLength", w.systemColumnsTableName, orgDatabase, PROMETHEUS_TABLE, w.systemColumnsTableName, orgDatabase, PROMETHEUS_TABLE)
	log.Info(sql)
	rows, err := w.ckdbConn.Query(sql)
	if err != nil {
		w.ckdbConn = nil
		return 0, err
	}

	for i := range rows {
		for rows[i].Next() {
			err := rows[i].Scan(&name)
			if err != nil {
				return 0, err
			}
			if maxName == "" || maxName < name {
				maxName = name
			}
		}
	}

	prefixLen := len("app_label_value_id_")
	if name == "" || len(name) <= prefixLen {
		return 0, fmt.Errorf("get max column name(%s) invalid", name)
	}

	indexStr := name[prefixLen:]
	return strconv.Atoi(indexStr)
}

func (w *PrometheusWriter) GetCounter() interface{} {
	var counter *Counter
	counter, w.counter = w.counter, &Counter{}
	return counter
}

// This function can be called when the FlowTags in the batch are the same (e.g. Prometheus metrics).
func (w *PrometheusWriter) WriteBatch(batch []interface{}, metricName string, timeSeries *prompb.TimeSeries, extraLabels []prompb.Label, tsLabelNameIDs, tsLabelValueIDs []uint32) {
	if len(batch) == 0 {
		return
	}

	// Only the FlowTag in the first item needs to be written.
	prometheusMetrics := batch[0].(PrometheusSampleInterface)
	ckwriter, err := w.getOrCreateCkwriter(prometheusMetrics)
	if err != nil {
		if w.counter.WriteErr == 0 {
			log.Warningf("get writer failed: %s", err)
		}
		atomic.AddInt64(&w.counter.WriteErr, 1)
		return
	}
	prometheusMetrics.GenerateNewFlowTags(w.flowTagWriter.Cache, metricName, timeSeries, extraLabels, tsLabelNameIDs, tsLabelValueIDs)
	w.flowTagWriter.WriteFieldsAndFieldValuesInCache()

	atomic.AddInt64(&w.counter.MetricsCount, int64(len(batch)))
	ckwriter.Put(batch...)
}

func NewPrometheusWriter(
	decoderIndex int,
	initAppLabelCount int,
	name string,
	db string,
	config *config.Config) (*PrometheusWriter, error) {

	// adjust CKWriterConfig
	ckWriterConfig := config.CKWriterConfig

	// FlowTagWriter
	flowTagWriterConfig := baseconfig.CKWriterConfig{
		QueueCount:   1,                        // Allocate one FlowTagWriter for each PrometheusWriter.
		QueueSize:    ckWriterConfig.QueueSize, // Only new FlowTags will be written, so the same QueueSize is used here.
		BatchSize:    ckWriterConfig.BatchSize,
		FlushTimeout: ckWriterConfig.FlushTimeout,
	}
	flowTagWriter, err := flow_tag.NewFlowTagWriter(decoderIndex, name, db, config.TTL, ckdb.TimeFuncTwelveHour, config.Base, &flowTagWriterConfig)
	if err != nil {
		return nil, err
	}
	systemColumnsTableName := "columns"
	if config.Base.CKDB.Type == ckdb.CKDBTypeByconity {
		systemColumnsTableName = "cnch_columns"
	}

	// PrometheusWriter
	writer := &PrometheusWriter{
		decoderIndex:            decoderIndex,
		name:                    name,
		ckdbAddrs:               config.Base.CKDB.ActualAddrs,
		currentCkdbAddrs:        utils.CloneStringSlice(*config.Base.CKDB.ActualAddrs),
		ckdbUsername:            config.Base.CKDBAuth.Username,
		ckdbPassword:            config.Base.CKDBAuth.Password,
		ckdbCluster:             config.Base.CKDB.ClusterName,
		ckdbStoragePolicy:       config.Base.CKDB.StoragePolicy,
		ckdbType:                config.Base.CKDB.Type,
		ckdbColdStorages:        config.Base.GetCKDBColdStorages(),
		ckdbTimeZone:            config.Base.CKDB.TimeZone,
		ttl:                     config.TTL,
		ckdbWatcher:             config.Base.CKDB.Watcher,
		writerConfig:            ckWriterConfig,
		flowTagWriter:           flowTagWriter,
		appLabelColumnIncrement: config.AppLabelColumnIncrement,
		systemColumnsTableName:  systemColumnsTableName,

		counter: &Counter{},
	}
	if err := writer.InitTable(initAppLabelCount); err != nil {
		return nil, err
	}
	baseconfig.AddClickHouseEndpointsOnChange(prometheusCKWriters)
	common.RegisterCountableForIngester("prometheus_writer", writer, stats.OptionStatTags{"msg": name, "decoder_index": strconv.Itoa(decoderIndex)})
	return writer, nil
}
