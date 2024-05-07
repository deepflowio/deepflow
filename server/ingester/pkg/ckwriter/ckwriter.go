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
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

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
	FLUSH_TIMEOUT        = 10 * time.Second
	SQL_LOG_LENGTH       = 256
	MAX_ORGANIZATINON_ID = 1024
)

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

	name         string // 数据库名-表名 用作 queue名字和counter名字
	prepare      string // 写入数据时，先执行prepare
	conns        []clickhouse.Conn
	batchs       []driver.Batch
	connCount    uint64
	dataQueues   queue.FixedMultiQueue
	counters     []Counter
	putCounter   int
	writeCounter uint64
	ckdbwatcher  *config.Watcher

	wg   sync.WaitGroup
	exit bool
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
	return conn.Exec(context.Background(), query)
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
	for _, view := range t.MakeViewsCreateSQLForDeepflowSystem(orgID) {
		if err := ExecSQL(conn, view); err != nil {
			return err
		}
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

func (w *CKWriter) InitTable(orgID uint16) error {
	for _, conn := range w.conns {
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
		err := InitTable(fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port), w.user, w.password, w.timeZone, w.table, orgID)
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
		log.Infof("database %s get orgIDs: %v", table.Database, orgIds)
		for _, orgId := range orgIds {
			if err = InitTable(addr, user, password, timeZone, table, orgId); err != nil {
				return nil, err
			}
		}
	}

	addrCount := len(addrs)
	conns := make([]clickhouse.Conn, addrCount)
	batchs := make([]driver.Batch, queueCount*addrCount)
	for i := 0; i < addrCount; i++ {
		if conns[i], err = clickhouse.Open(&clickhouse.Options{
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

	name := fmt.Sprintf("%s-%s-%s", table.Database, table.LocalName, counterName)
	dataQueues := queue.NewOverwriteQueues(
		name, queue.HashKey(queueCount), queueSize,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(CKItem).Release() }),
		common.QUEUE_STATS_MODULE_INGESTER)

	return &CKWriter{
		addrs:         addrs,
		user:          user,
		password:      password,
		timeZone:      timeZone,
		table:         table,
		queueCount:    queueCount,
		queueSize:     queueSize,
		batchSize:     batchSize,
		flushDuration: time.Duration(flushTimeout) * time.Second,
		counterName:   counterName,

		name:        name,
		prepare:     table.MakePrepareTableInsertSQL(),
		conns:       conns,
		batchs:      batchs,
		connCount:   uint64(len(conns)),
		dataQueues:  dataQueues,
		counters:    make([]Counter, queueCount),
		ckdbwatcher: ckdbwatcher,
	}, nil
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
	orgID         uint16
	prepare       string
	items         []CKItem
	lastWriteTime time.Time
	tableCreated  bool
}

func (c *Cache) Release() {
	for _, item := range c.items {
		item.Release()
	}
	c.items = c.items[:0]
}

func (w *CKWriter) queueProcess(queueID int) {
	common.RegisterCountableForIngester("ckwriter", &(w.counters[queueID]), stats.OptionStatTags{"thread": strconv.Itoa(queueID), "table": w.name, "name": w.counterName})
	defer w.wg.Done()
	w.wg.Add(1)

	rawItems := make([]interface{}, 1024)
	var cache *Cache
	orgCaches := make([]*Cache, MAX_ORGANIZATINON_ID+1)
	for i := range orgCaches {
		orgCaches[i] = new(Cache)
		orgCaches[i].items = make([]CKItem, 0)
		orgCaches[i].orgID = uint16(i)
		orgCaches[i].prepare = w.table.MakeOrgPrepareTableInsertSQL(uint16(i))
	}

	for !w.exit {
		n := w.dataQueues.Gets(queue.HashKey(queueID), rawItems)
		for i := 0; i < n; i++ {
			item := rawItems[i]
			if ck, ok := item.(CKItem); ok {
				orgID := ck.OrgID()
				if orgID > MAX_ORGANIZATINON_ID {
					if w.counters[queueID].OrgInvalidCount == 0 {
						log.Warningf("writer queue (%s) item wrong orgID %d", w.name, orgID)
					}
					w.counters[queueID].OrgInvalidCount++
					continue
				}
				cache = orgCaches[orgID]
				cache.items = append(cache.items, ck)
				if len(cache.items) >= w.batchSize {
					w.Write(queueID, cache)
					cache.lastWriteTime = time.Now()
				}
			} else if IsNil(item) { // flush ticker
				now := time.Now()
				for _, cache := range orgCaches {
					if len(cache.items) > 0 && now.Sub(cache.lastWriteTime) > w.flushDuration {
						w.Write(queueID, cache)
						cache.lastWriteTime = now
					}
				}
			} else {
				log.Warningf("get writer queue data type wrong %T", ck)
			}
		}
	}
}

func (w *CKWriter) ResetConnection(connID int) error {
	var err error
	// FIXME: do reset actually
	if !IsNil(w.conns[connID]) {
		return nil
	}
	w.conns[connID], err = clickhouse.Open(&clickhouse.Options{
		Addr: []string{w.addrs[connID]},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: w.user,
			Password: w.password,
		},
	})
	return err
}

func (w *CKWriter) Write(queueID int, cache *Cache) {
	connID := int(atomic.AddUint64(&w.writeCounter, 1) % w.connCount)
	itemsLen := len(cache.items)
	// Prevent frequent log writing
	logEnabled := w.counters[queueID].WriteFailedCount == 0
	if !cache.tableCreated {
		err := w.InitTable(cache.orgID)
		if err != nil {
			if logEnabled {
				log.Warningf("create table (%s.%s) failed, drop (%d) items: %s", w.table.OrgDatabase(cache.orgID), w.table.LocalName, itemsLen, err)
			}
			w.counters[queueID].WriteFailedCount += int64(itemsLen)
			cache.Release()
			return
		}
		cache.tableCreated = true
	}
	if err := w.writeItems(queueID, connID, cache); err != nil {
		if logEnabled {
			log.Warningf("write table (%s.%s) failed, will retry write (%d) items: %s", w.table.OrgDatabase(cache.orgID), w.table.LocalName, itemsLen, err)
		}
		if err := w.ResetConnection(connID); err != nil {
			log.Warningf("reconnect clickhouse failed: %s", err)
			time.Sleep(time.Second * 10)
		} else {
			if logEnabled {
				log.Infof("reconnect clickhouse success: %s %s", w.table.OrgDatabase(cache.orgID), w.table.LocalName)
			}
		}

		w.counters[queueID].RetryCount++
		// 写失败重连后重试一次, 规避偶尔写失败问题
		err = w.writeItems(queueID, connID, cache)
		if logEnabled {
			if err != nil {
				w.counters[queueID].RetryFailedCount++
				log.Warningf("retry write table (%s.%s) failed, drop (%d) items: %s", w.table.OrgDatabase(cache.orgID), w.table.LocalName, itemsLen, err)
			} else {
				log.Infof("retry write table (%s.%s) success, write (%d) items", w.table.OrgDatabase(cache.orgID), w.table.LocalName, itemsLen)
			}
		}
		if err != nil {
			w.counters[queueID].WriteFailedCount += int64(itemsLen)
		} else {
			w.counters[queueID].WriteSuccessCount += int64(itemsLen)
		}
	} else {
		w.counters[queueID].WriteSuccessCount += int64(itemsLen)
	}

	cache.Release()
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

func (w *CKWriter) writeItems(queueID, connID int, cache *Cache) error {
	if len(cache.items) == 0 {
		return nil
	}
	ck := w.conns[connID]
	if IsNil(ck) {
		if err := w.ResetConnection(connID); err != nil {
			time.Sleep(time.Second * 10)
			return fmt.Errorf("write block failed, can not connect to clickhouse: %s", err)
		}
		ck = w.conns[connID]
	}
	var err error
	batchID := queueID*int(w.connCount) + connID
	batch := w.batchs[batchID]
	if IsNil(batch) {
		w.batchs[batchID], err = ck.PrepareBatch(context.Background(), cache.prepare)
		if err != nil {
			return fmt.Errorf("prepare batch item write block failed: %s", err)
		}
		batch = w.batchs[batchID]
	} else {
		batch, err = ck.PrepareReuseBatch(context.Background(), cache.prepare, batch)
		if err != nil {
			return fmt.Errorf("prepare reuse batch item write block failed: %s", err)
		}
		w.batchs[batchID] = batch
	}

	ckdbBlock := ckdb.NewBlock(batch)
	for _, item := range cache.items {
		item.WriteBlock(ckdbBlock)
		if err := ckdbBlock.WriteAll(); err != nil {
			return fmt.Errorf("item write block failed: %s", err)
		}
	}
	if err = ckdbBlock.Send(); err != nil {
		return fmt.Errorf("send write block failed: %s", err)
	} else {
		log.Debugf("batch write success, table (%s.%s) commit %d items", w.table.Database, w.table.LocalName, len(cache.items))
	}
	return nil
}

func (w *CKWriter) Close() {
	w.exit = true
	w.wg.Wait()
	for i, c := range w.conns {
		if !IsNil(c) {
			c.Close()
			w.conns[i] = nil
		}
	}
	for _, c := range w.counters {
		c.Close()
	}

	for _, q := range w.dataQueues {
		q.Close()
	}

	log.Infof("ckwriter %s closed", w.name)
}
