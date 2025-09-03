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

package ckwriter

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	server_common "github.com/deepflowio/deepflow/server/common"
	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("ckwriter")

const (
	FLUSH_TIMEOUT     = 10 * time.Second
	SQL_LOG_LENGTH    = 256
	SQL_RESULT_LENGTH = 1024
	RETRY_COUNT       = 2
)

var ckwriterManager = &CKWriterManager{}

type CKWriterManager struct {
	ckwriters []*CKWriter
	sync.Mutex
}

func RegisterToCkwriterManager(w *CKWriter) {
	ckwriterManager.Lock()
	if len(ckwriterManager.ckwriters) == 0 {
		server_common.SetOrgHandler(ckwriterManager)
		config.AddClickHouseEndpointsOnChange(ckwriterManager)
	}
	ckwriterManager.ckwriters = append(ckwriterManager.ckwriters, w)
	ckwriterManager.Unlock()
}

func (m *CKWriterManager) DropOrg(orgId uint16) error {
	log.Infof("call ckwriters drop org %d", orgId)
	ckwriterManager.Lock()
	for _, ckwriter := range m.ckwriters {
		log.Infof("ckwriter %s drop org %d", ckwriter.name, orgId)
		ckwriter.dropOrg(orgId)
	}
	ckwriterManager.Unlock()
	return nil
}

func (m *CKWriterManager) EndpointsChange(addrs []string) {
	ckwriterManager.Lock()
	for _, ckwriter := range m.ckwriters {
		log.Infof("ckwriter %s addrs change from %s to %s ", ckwriter.name, ckwriter.addrs, addrs)
		ckwriter.addrs = utils.CloneStringSlice(addrs)
		ckwriter.endpointsChange(addrs)
	}
	ckwriterManager.Unlock()
}

type CKWriter struct {
	addrs         []string
	user          string
	password      string
	timeZone      string
	table         *ckdb.Table
	queueCount    int
	queueSize     int           // 队列长度
	batchSize     int           // 累积多少行数据，一起写入
	flushDuration time.Duration // 超时写入
	counterName   string        // 写入成功失败的统计数据表名称，若写入失败，会根据该数据上报告警

	name          string // 数据库名-表名 用作 queue名字和counter名字
	prepare       string // 写入数据时，先执行prepare
	dataQueues    queue.FixedMultiQueue
	putCounter    int
	ckdbwatcher   *config.Watcher
	queueContexts []*QueueContext

	wg   sync.WaitGroup
	exit bool
}

type QueueContext struct {
	endpointsChange bool
	orgCaches       []*Cache // write caches for all organizations
	user, password  string
	conns           []clickhouse.Conn
	connCount       int
	counter         Counter
}

func (qc *QueueContext) EndpointsChange(addrs []string) {
	if !qc.endpointsChange || len(addrs) == 0 {
		return
	}
	for _, conn := range qc.conns {
		if conn != nil {
			conn.Close()
		}
	}
	qc.connCount = len(addrs)
	qc.conns = make([]clickhouse.Conn, qc.connCount)
	for i, addr := range addrs {
		qc.conns[i], _ = clickhouse.Open(&clickhouse.Options{
			Addr: []string{addr},
			Auth: clickhouse.Auth{
				Database: "default",
				Username: qc.user,
				Password: qc.password,
			},
			DialTimeout: 5 * time.Second,
		})
	}
	qc.endpointsChange = false
	for _, cache := range qc.orgCaches {
		cache.tableCreated = false
	}
}

type CKItem interface {
	WriteBlock(block *ckdb.Block)
	OrgID() uint16
	Release()
}

func ExecSQL(conn clickhouse.Conn, query string) error {
	if len(query) > SQL_LOG_LENGTH {
		log.Infof("Exec SQL: %s ...", query[:SQL_LOG_LENGTH])
	} else {
		log.Info("Exec SQL: ", query)
	}
	err := conn.Exec(context.Background(), query)
	retryTimes := RETRY_COUNT
	for err != nil && retryTimes > 0 {
		log.Warningf("Exec SQL (%s) failed: %s, will retry", query, err)
		time.Sleep(time.Second)
		err = conn.Exec(context.Background(), query)
		if err == nil {
			log.Infof("Retry exec SQL (%s) success", query)
			return nil
		}
		retryTimes--
	}
	return err
}

func QuerySQLStringResult(conn clickhouse.Conn, query string) (string, error) {
	if len(query) > SQL_LOG_LENGTH {
		log.Infof("Query SQL: %s ...", query[:SQL_LOG_LENGTH])
	} else {
		log.Info("Query SQL: ", query)
	}

	rows, err := conn.Query(context.Background(), query)
	if err != nil {
		return "", fmt.Errorf("query failed: %v", err)
	}
	defer rows.Close()

	columns := rows.Columns()
	if len(columns) == 0 {
		return "", fmt.Errorf("no columns in result")
	}

	var result strings.Builder
	result.WriteString(strings.Join(columns, "\t") + "\n")

	values := make([]interface{}, len(columns))
	for i := range values {
		values[i] = new(string)
	}

	for rows.Next() {
		if err := rows.Scan(values...); err != nil {
			return "", fmt.Errorf("scan row failed: %v", err)
		}

		rowValues := make([]string, len(values))
		for i, val := range values {
			rowValues[i] = *(val.(*string))
		}
		result.WriteString(strings.Join(rowValues, "\t") + "\n")
	}

	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("rows error: %v", err)
	}

	r := result.String()
	if len(query) > SQL_RESULT_LENGTH {
		log.Infof("Query SQL result: %s ...", r[:SQL_RESULT_LENGTH])
	} else {
		log.Info("Query SQL result: ", r)
	}
	return r, nil
}

func initTable(conn clickhouse.Conn, timeZone string, t *ckdb.Table, orgID uint16) error {
	if err := ExecSQL(conn, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", t.OrgDatabase(orgID))); err != nil {
		return err
	}

	if err := ExecSQL(conn, t.MakeOrgLocalTableCreateSQL(orgID)); err != nil {
		return err
	}
	if err := ExecSQL(conn, t.MakeOrgGlobalTableCreateSQL(orgID)); err != nil {
		return err
	}

	if t.Aggr1H1D {
		aggrTableCreateSQL, err := QuerySQLStringResult(conn, fmt.Sprintf("SHOW CREATE TABLE %s", t.AggrTable1H(orgID)))
		if err != nil {
			log.Warningf("query 1h agg table failed: %s", err)
		}
		if t.IsAggrTableWrong(aggrTableCreateSQL) {
			if err := ExecSQL(conn, t.MakeAggrTableRenameSQL1H(orgID)); err != nil {
				log.Warningf("drop 1h agg table failed: %s", err)
			}
		}

		if err := ExecSQL(conn, t.MakeAggrTableCreateSQL1H(orgID)); err != nil {
			log.Warningf("create 1h agg table failed: %s", err)
		}
		if err := ExecSQL(conn, t.MakeAggrMVTableCreateSQL1H(orgID)); err != nil {
			log.Warningf("create 1h mv table failed: %s", err)
		}
		if err := ExecSQL(conn, t.MakeAggrLocalTableCreateSQL1H(orgID)); err != nil {
			log.Warningf("create 1h local table failed: %s", err)
		}
		if err := ExecSQL(conn, t.MakeAggrGlobalTableCreateSQL1H(orgID)); err != nil {
			log.Warningf("create 1h global table failed: %s", err)
		}

		aggrTableCreateSQL, err = QuerySQLStringResult(conn, fmt.Sprintf("SHOW CREATE TABLE %s", t.AggrTable1D(orgID)))
		if err != nil {
			log.Warningf("query 1d agg table failed: %s", err)
		}
		if t.IsAggrTableWrong(aggrTableCreateSQL) {
			if err := ExecSQL(conn, t.MakeAggrTableRenameSQL1D(orgID)); err != nil {
				log.Warningf("drop 1d agg table failed: %s", err)
			}
		}
		if err := ExecSQL(conn, t.MakeAggrTableCreateSQL1D(orgID)); err != nil {
			log.Warningf("create 1d agg table failed: %s", err)
		}
		if err := ExecSQL(conn, t.MakeAggrMVTableCreateSQL1D(orgID)); err != nil {
			log.Warningf("create 1d mv table failed: %s", err)
		}
		if err := ExecSQL(conn, t.MakeAggrLocalTableCreateSQL1D(orgID)); err != nil {
			log.Warningf("create 1d local table failed: %s", err)
		}
		if err := ExecSQL(conn, t.MakeAggrGlobalTableCreateSQL1D(orgID)); err != nil {
			log.Warningf("create 1d global table failed: %s", err)
		}
	}

	if t.Aggr1S {
		aggrTableCreateSQL, err := QuerySQLStringResult(conn, fmt.Sprintf("SHOW CREATE TABLE %s", t.AggrTable1S(orgID)))
		if err != nil {
			log.Warningf("query 1s agg table failed: %s", err)
		}
		if t.IsAggrTableWrong(aggrTableCreateSQL) {
			if err := ExecSQL(conn, t.MakeAggrTableRenameSQL1S(orgID)); err != nil {
				log.Warningf("drop 1s agg table failed: %s", err)
			}
		}

		localTableCreateSQL, err := QuerySQLStringResult(conn, fmt.Sprintf("SHOW CREATE TABLE %s", t.LocalTable1S(orgID)))
		if err != nil {
			log.Warningf("query 1s local table failed: %s", err)
		}

		if t.IsLocalTableWrong(localTableCreateSQL) {
			if err := ExecSQL(conn, t.MakeLocalTableDropSQL1S(orgID)); err != nil {
				log.Warningf("drop 1s local table failed: %s", err)
			}
		}

		if err := ExecSQL(conn, t.MakeAggrTableCreateSQL1S(orgID)); err != nil {
			log.Warningf("create 1s agg table failed: %s", err)
		}
		if err := ExecSQL(conn, t.MakeAggrMVTableCreateSQL1S(orgID)); err != nil {
			log.Warningf("create 1s mv table failed: %s", err)
		}
		if err := ExecSQL(conn, t.MakeAggrLocalTableCreateSQL1S(orgID)); err != nil {
			log.Warningf("create 1s local table failed: %s", err)
		}
		if err := ExecSQL(conn, t.MakeAggrGlobalTableCreateSQL1S(orgID)); err != nil {
			log.Warningf("create 1s global table failed: %s", err)
		}

	}

	// ByConity not support modify timezone
	if t.DBType == ckdb.CKDBTypeByconity {
		return nil
	}

	for _, c := range t.Columns {
		for _, table := range []string{t.GlobalName, t.LocalName} {
			modTimeZoneSql := c.MakeModifyTimeZoneSQL(t.OrgDatabase(orgID), table, timeZone)
			if modTimeZoneSql == "" {
				break
			}

			if err := ExecSQL(conn, modTimeZoneSql); err != nil {
				log.Warningf("modify time zone failed, error: %s", err)
			}
		}
	}

	return nil
}

func InitTable(addr, user, password, timeZone string, t *ckdb.Table, orgID uint16) error {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: user,
			Password: password,
		},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return err
	}

	if err := initTable(conn, timeZone, t, orgID); err != nil {
		conn.Close()
		return err
	}
	conn.Close()

	return nil
}

func (w *CKWriter) InitTable(queueID int, orgID uint16) error {
	for _, conn := range w.queueContexts[queueID].conns {
		if err := initTable(conn, w.timeZone, w.table, orgID); err != nil {
			return err
		}
	}

	// in standalone mode, ckdbWatcher will be nil
	if w.ckdbwatcher == nil {
		return nil
	}

	endpoints, err := w.ckdbwatcher.GetClickhouseEndpointsWithoutMyself()
	if err != nil {
		log.Warningf("get clickhouse endpoints without myself failed: %s", err)
		return err
	}

	for _, endpoint := range endpoints {
		err := InitTable(net.JoinHostPort(endpoint.Host, fmt.Sprintf("%d", endpoint.Port)), w.user, w.password, w.timeZone, w.table, orgID)
		if err != nil {
			log.Warningf("node %s:%d init table failed. err: %s", endpoint.Host, endpoint.Port, err)
		} else {
			log.Infof("node %s:%d init table %s success", endpoint.Host, endpoint.Port, w.table.LocalName)
		}
	}

	return nil
}

func NewCKWriter(addrs []string, user, password, counterName, timeZone string, table *ckdb.Table, queueCount, queueSize, batchSize, flushTimeout int, ckdbwatcher *config.Watcher) (*CKWriter, error) {
	log.Infof("New CK writer: Addrs=%v, user=%s, database=%s, table=%s, queueCount=%d, queueSize=%d, batchSize=%d, flushTimeout=%ds, counterName=%s, timeZone=%s",
		addrs, user, table.Database, table.LocalName, queueCount, queueSize, batchSize, flushTimeout, counterName, timeZone)

	if len(addrs) == 0 {
		return nil, fmt.Errorf("addrs is empty")
	}

	var err error

	// clickhouse init default organization database/tables
	for _, addr := range addrs {
		orgIds := grpc.QueryAllOrgIDs()
		if len(orgIds) > 1 {
			log.Infof("database %s get orgIDs: %v", table.Database, orgIds)
		}
		for _, orgId := range orgIds {
			if err = InitTable(addr, user, password, timeZone, table, orgId); err != nil {
				return nil, err
			}
		}
	}

	addrCount := len(addrs)
	queueContexts := make([]*QueueContext, queueCount)
	for i := range queueContexts {
		queueContexts[i] = &QueueContext{}
		qc := queueContexts[i]
		qc.connCount = addrCount
		qc.conns = make([]clickhouse.Conn, addrCount)
		for i := 0; i < addrCount; i++ {
			if qc.conns[i], err = clickhouse.Open(&clickhouse.Options{
				Addr: []string{addrs[i]},
				Auth: clickhouse.Auth{
					Database: "default",
					Username: user,
					Password: password,
				},
				ConnMaxLifetime: time.Hour * 24,
			}); err != nil {
				return nil, err
			}
		}
		orgCaches := make([]*Cache, ckdb.MAX_ORG_ID+1)
		for i := range orgCaches {
			orgCaches[i] = new(Cache)
			orgCaches[i].orgID = uint16(i)
			orgCaches[i].queueContext = qc
			orgCaches[i].prepare = table.MakeOrgPrepareTableInsertSQL(uint16(i))
		}
		qc.orgCaches = orgCaches
		qc.user, qc.password = user, password
	}

	name := fmt.Sprintf("%s-%s-%s", table.Database, table.LocalName, counterName)
	dataQueues := queue.NewOverwriteQueues(
		name, queue.HashKey(queueCount), queueSize,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(CKItem).Release() }),
		common.QUEUE_STATS_MODULE_INGESTER)

	w := &CKWriter{
		addrs:         utils.CloneStringSlice(addrs),
		user:          user,
		password:      password,
		timeZone:      timeZone,
		table:         table,
		queueCount:    queueCount,
		queueSize:     queueSize,
		batchSize:     batchSize,
		flushDuration: time.Duration(flushTimeout) * time.Second,
		counterName:   counterName,
		queueContexts: queueContexts,

		name:        name,
		prepare:     table.MakePrepareTableInsertSQL(),
		dataQueues:  dataQueues,
		ckdbwatcher: ckdbwatcher,
	}
	RegisterToCkwriterManager(w)
	return w, nil
}

func (w *CKWriter) dropOrg(orgId uint16) {
	for i, qc := range w.queueContexts {
		log.Debugf("ckwriter %s queue %d drop org %d", w.name, i, orgId)
		qc.orgCaches[orgId].dropTime = uint32(time.Now().Unix())
		qc.orgCaches[orgId].tableCreated = false
	}
}

func (w *CKWriter) endpointsChange(addrs []string) {
	for i := 0; i < len(w.queueContexts); i++ {
		log.Debugf("ckwriter %s queue %d endpoints will change to %s", w.name, i, addrs)
		w.queueContexts[i].endpointsChange = true
	}
}

func (w *CKWriter) Run() {
	for i := 0; i < w.queueCount; i++ {
		go w.queueProcess(i)
	}
}

type Counter struct {
	WriteSuccessCount int64 `statsd:"write-success-count"`
	WriteFailedCount  int64 `statsd:"write-failed-count"`
	RetryCount        int64 `statsd:"retry-count"`
	RetryFailedCount  int64 `statsd:"retry-failed-count"`
	OrgInvalidCount   int64 `statsd:"org-invalid-count"`
	utils.Closable
}

func (i *Counter) GetCounter() interface{} {
	var counter Counter
	counter, *i = *i, Counter{}

	return &counter
}

func (w *CKWriter) Put(items ...interface{}) {
	if w.queueSize == 0 {
		for _, item := range items {
			if ck, ok := item.(CKItem); ok {
				ck.Release()
			}
		}
		return
	}
	w.putCounter++
	w.dataQueues.Put(queue.HashKey(w.putCounter%w.queueCount), items...)
}

type Cache struct {
	queueContext  *QueueContext
	orgID         uint16
	prepare       string
	block         *ckdb.Block
	batch         driver.Batch
	batchSize     int
	writeCounter  int
	lastWriteTime time.Time
	tableCreated  bool
	dropTime      uint32
}

func (c *Cache) Release() {
	c.block = nil
	c.batch = nil
}

func (c *Cache) OrgIdExists() bool {
	updateTime, exists := grpc.QueryOrgIDExist(c.orgID)
	if updateTime == 0 || c.dropTime == 0 {
		return exists
	}
	// dropped but not update org id list, return false
	if updateTime <= c.dropTime {
		return false
	}
	c.dropTime = 0
	return exists
}

func (w *CKWriter) queueProcess(queueID int) {
	qc := w.queueContexts[queueID]
	common.RegisterCountableForIngester("ckwriter", &(qc.counter), stats.OptionStatTags{"thread": strconv.Itoa(queueID), "table": w.name, "name": w.counterName})

	w.wg.Add(1)
	defer w.wg.Done()

	rawItems := make([]interface{}, 1024)
	orgCaches := qc.orgCaches

	for !w.exit {
		n := w.dataQueues.Gets(queue.HashKey(queueID), rawItems)
		for i := 0; i < n; i++ {
			item := rawItems[i]
			if ckItem, ok := item.(CKItem); ok {
				orgID := ckItem.OrgID()
				if orgID > ckdb.MAX_ORG_ID {
					if qc.counter.OrgInvalidCount == 0 {
						log.Warningf("writer queue (%s) item wrong orgID %d", w.name, orgID)
					}
					qc.counter.OrgInvalidCount++
					continue
				}
				cache := orgCaches[orgID]
				cache.Add(ckItem)
				if cache.batchSize >= w.batchSize {
					w.Write(queueID, cache)
				}
			} else if IsNil(item) { // flush ticker
				now := time.Now()
				for _, cache := range orgCaches {
					if cache.batchSize > 0 && now.Sub(cache.lastWriteTime) > w.flushDuration {
						w.Write(queueID, cache)
					}
				}
			} else {
				log.Warningf("get writer queue data type wrong %T", item)
			}
		}
	}
}

func (c *Cache) initBatch() error {
	var err error
	conn := c.queueContext.conns[c.writeCounter%c.queueContext.connCount]
	if IsNil(c.batch) {
		c.batch, err = conn.PrepareBatch(context.Background(), c.prepare)
		if err != nil {
			return fmt.Errorf("prepare batch item write block failed: %s", err)
		}
	}
	if c.block == nil {
		c.block = ckdb.NewBlock(c.batch)
	}
	return nil
}

func (c *Cache) Add(item CKItem) error {
	if err := c.initBatch(); err != nil {
		return err
	}

	item.WriteBlock(c.block)
	if err := c.block.WriteAll(); err != nil {
		item.Release()
		return fmt.Errorf("item write block failed: %s", err)
	}
	item.Release()
	c.batchSize++
	return nil
}

func (c *Cache) Write() error {
	if c.batchSize == 0 || IsNil(c.batch) {
		return nil
	}
	conn := c.queueContext.conns[c.writeCounter%c.queueContext.connCount]
	batch, err := conn.PrepareReuseBatch(context.Background(), c.prepare, c.batch)
	if err != nil {
		return fmt.Errorf("prepare reuse batch item write block failed: %s", err)
	}
	c.batch = batch

	err = c.batch.Send()
	c.batch.Reset()
	c.writeCounter++
	c.lastWriteTime = time.Now()
	c.batchSize = 0
	if err != nil {
		return fmt.Errorf("cache send write block failed: %s", err)
	}
	return nil
}

func (w *CKWriter) ResetConnection(queueID, connID int) error {
	var err error
	// FIXME: do reset actually
	if !IsNil(w.queueContexts[queueID].conns[connID]) {
		return nil
	}
	w.queueContexts[queueID].conns[connID], err = clickhouse.Open(&clickhouse.Options{
		Addr: []string{w.addrs[connID]},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: w.user,
			Password: w.password,
		},
		DialTimeout: 5 * time.Second,
	})
	return err
}

func (w *CKWriter) Write(queueID int, cache *Cache) {
	qc := w.queueContexts[queueID]
	qc.EndpointsChange(w.addrs)
	itemsLen := cache.batchSize
	// Prevent frequent log writing
	logEnabled := qc.counter.WriteFailedCount == 0
	if !cache.OrgIdExists() {
		if logEnabled {
			log.Warningf("table (%s.%s) orgId is not exist, drop (%d) items", w.table.OrgDatabase(cache.orgID), w.table.LocalName, itemsLen)
		}
		qc.counter.OrgInvalidCount += int64(itemsLen)
		cache.Release()
		return
	}
	if !cache.tableCreated {
		err := w.InitTable(queueID, cache.orgID)
		if err != nil {
			if logEnabled {
				log.Warningf("create table (%s.%s) failed, drop (%d) items: %s", w.table.OrgDatabase(cache.orgID), w.table.LocalName, itemsLen, err)
			}
			qc.counter.WriteFailedCount += int64(itemsLen)
			cache.Release()
			return
		}
		cache.tableCreated = true
	}
	if err := cache.Write(); err != nil {
		if logEnabled {
			log.Warningf("write table (%s.%s) failed, drop (%d) items: %s", w.table.OrgDatabase(cache.orgID), w.table.LocalName, itemsLen, err)
		}
		qc.counter.WriteFailedCount += int64(itemsLen)
	} else {
		qc.counter.WriteSuccessCount += int64(itemsLen)
	}
}

func IsNil(i interface{}) bool {
	if i == nil {
		return true
	}
	vi := reflect.ValueOf(i)
	if vi.Kind() == reflect.Ptr {
		return vi.IsNil()
	}
	return false
}

func (w *CKWriter) Close() {
	w.exit = true
	w.wg.Wait()
	for _, qc := range w.queueContexts {
		for i, c := range qc.conns {
			if !IsNil(c) {
				c.Close()
				qc.conns[i] = nil
			}
		}
		qc.counter.Close()
	}

	for _, q := range w.dataQueues {
		q.Close()
	}

	log.Infof("ckwriter %s closed", w.name)
}
