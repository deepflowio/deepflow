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

package ckwriter

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/deepflowys/deepflow/server/ingester/common"
	"github.com/deepflowys/deepflow/server/libs/ckdb"
	"github.com/deepflowys/deepflow/server/libs/queue"
	"github.com/deepflowys/deepflow/server/libs/stats"
	"github.com/deepflowys/deepflow/server/libs/utils"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("ckwriter")

const (
	FLUSH_TIMEOUT  = 10 * time.Second
	SQL_LOG_LENGTH = 256
)

type CKWriter struct {
	primaryAddr   string
	secondaryAddr string
	user          string
	password      string
	table         *ckdb.Table
	queueCount    int
	queueSize     int    // 队列长度
	batchSize     int    // 累积多少行数据，一起写入
	flushTimeout  int    // 超时写入： 单位秒
	counterName   string // 写入成功失败的统计数据表名称，若写入失败，会根据该数据上报告警

	name       string // 数据库名-表名 用作 queue名字和counter名字
	prepare    string // 写入数据时，先执行prepare
	conns      []clickhouse.Conn
	dataQueues queue.FixedMultiQueue
	counters   []Counter
	putCounter int

	wg   sync.WaitGroup
	exit bool
}

type CKItem interface {
	WriteBlock(block *ckdb.Block) error
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

func InitTable(addr, user, password string, t *ckdb.Table) error {
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

	if err := ExecSQL(conn, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", t.Database)); err != nil {
		return err
	}

	if err := ExecSQL(conn, t.MakeLocalTableCreateSQL()); err != nil {
		return err
	}
	if err := ExecSQL(conn, t.MakeGlobalTableCreateSQL()); err != nil {
		return err
	}
	conn.Close()
	return nil
}

func initReplicaTable(addr, user, password string, t *ckdb.Table) {
	for {
		if err := InitTable(addr, user, password, t); err != nil {
			log.Warningf("Init replica(%s) table failed, will retry after one minute. %s", addr, err)
			time.Sleep(time.Minute)
			continue
		}
		return
	}
}

func NewCKWriter(primaryAddr, secondaryAddr, user, password, counterName string, table *ckdb.Table, replicaEnabled bool, queueCount, queueSize, batchSize, flushTimeout int) (*CKWriter, error) {
	log.Infof("New CK writer: primaryAddr=%s, secondaryAddr=%s, user=%s, database=%s, table=%s, replica=%v, queueCount=%d, queueSize=%d, batchSize=%d, flushTimeout=%ds",
		primaryAddr, secondaryAddr, user, table.Database, table.LocalName, replicaEnabled, queueCount, queueSize, batchSize, flushTimeout)

	conns := make([]clickhouse.Conn, queueCount)
	var err error

	// primary clickhouse的初始化创建表
	if err = InitTable(primaryAddr, user, password, table); err != nil {
		return nil, err
	}

	// secondaryAddr作为replica clickhouse, 只需要初始化建表
	if replicaEnabled {
		if err := InitTable(secondaryAddr, user, password, table); err != nil {
			// replica 创建table失败，每隔1分钟后台重试创建
			go initReplicaTable(secondaryAddr, user, password, table)
		}
	} else if len(secondaryAddr) > 0 {
		// FIXME secondaryAddr也作为primary clickhouse时, 只支持初始化建表, 不支持写入
		if err = InitTable(secondaryAddr, user, password, table); err != nil {
			return nil, err
		}
	}

	for i := 0; i < queueCount; i++ {
		if conns[i], err = clickhouse.Open(&clickhouse.Options{
			Addr: []string{primaryAddr},
			Auth: clickhouse.Auth{
				Database: "default",
				Username: user,
				Password: password,
			},
		}); err != nil {
			return nil, err
		}
	}

	name := fmt.Sprintf("%s-%s", table.Database, table.LocalName)
	dataQueues := queue.NewOverwriteQueues(
		name, queue.HashKey(queueCount), queueSize,
		queue.OptionFlushIndicator(time.Second),
		queue.OptionRelease(func(p interface{}) { p.(CKItem).Release() }),
		common.QUEUE_STATS_MOUDLE_INGESTER)

	return &CKWriter{
		primaryAddr:   primaryAddr,
		secondaryAddr: secondaryAddr,
		table:         table,
		queueCount:    queueCount,
		queueSize:     queueSize,
		batchSize:     batchSize,
		flushTimeout:  flushTimeout,
		counterName:   counterName,

		name:       name,
		prepare:    table.MakePrepareTableInsertSQL(),
		conns:      conns,
		dataQueues: dataQueues,
		counters:   make([]Counter, queueCount),
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
	utils.Closable
}

func (i *Counter) GetCounter() interface{} {
	var counter Counter
	counter, *i = *i, Counter{}

	return &counter
}

func (w *CKWriter) Put(items ...interface{}) {
	w.putCounter++
	w.dataQueues.Put(queue.HashKey(w.putCounter%w.queueCount), items...)
}

func (w *CKWriter) queueProcess(queueID int) {
	common.RegisterCountableForIngester("ckwriter", &(w.counters[queueID]), stats.OptionStatTags{"thread": strconv.Itoa(queueID), "table": w.name, "name": w.counterName})
	defer w.wg.Done()
	w.wg.Add(1)

	var lastWriteTime time.Time

	rawItems := make([]interface{}, 1024)
	caches := make([]CKItem, 0, w.batchSize)
	for !w.exit {
		n := w.dataQueues.Gets(queue.HashKey(queueID), rawItems)
		for i := 0; i < n; i++ {
			item := rawItems[i]
			if ck, ok := item.(CKItem); ok {
				caches = append(caches, ck)
				if len(caches) >= w.batchSize {
					w.Write(queueID, caches)
					caches = caches[:0]
					lastWriteTime = time.Now()
				}
			} else if IsNil(item) { // flush ticker
				if time.Since(lastWriteTime) > time.Duration(w.flushTimeout)*time.Second {
					w.Write(queueID, caches)
					caches = caches[:0]
					lastWriteTime = time.Now()
				}
			} else {
				log.Warningf("get writer queue data type wrong %T", ck)
			}
		}
	}
}

func (w *CKWriter) ResetConnection(queueID int) error {
	var err error
	if !IsNil(w.conns[queueID]) {
		w.conns[queueID].Close()
		w.conns[queueID] = nil
	}
	if w.conns[queueID], err = clickhouse.Open(&clickhouse.Options{
		Addr: []string{w.primaryAddr},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: w.user,
			Password: w.password,
		},
	}); err != nil {
		return err
	}
	return nil
}

func (w *CKWriter) Write(queueID int, items []CKItem) {
	if err := w.writeItems(queueID, items); err != nil {
		if w.counters[queueID].WriteFailedCount == 0 {
			log.Warningf("write table(%s.%s) failed, will retry write(%d) items: %s", w.table.Database, w.table.LocalName, len(items), err)
			if err := w.ResetConnection(queueID); err != nil {
				log.Warningf("reconnect clickhouse failed: %s", err)
				time.Sleep(time.Minute)
			} else {
				log.Infof("reconnect clickhouse success: %s %s", w.table.Database, w.table.LocalName)
			}

			// 写失败重连后重试一次, 规避偶尔写失败问题
			if err = w.writeItems(queueID, items); err != nil {
				log.Warningf("retry write table(%s.%s) failed, drop(%d) items: %s", w.table.Database, w.table.LocalName, len(items), err)
			} else {
				log.Infof("retry write table(%s.%s) success, write(%d) items", w.table.Database, w.table.LocalName, len(items))
			}
		}
		if err != nil {
			w.counters[queueID].WriteFailedCount += int64(len(items))
		} else {
			w.counters[queueID].WriteSuccessCount += int64(len(items))
		}
	} else {
		w.counters[queueID].WriteSuccessCount += int64(len(items))
	}

	for _, item := range items {
		item.Release()
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

func (w *CKWriter) writeItems(queueID int, items []CKItem) error {
	if len(items) == 0 {
		return nil
	}
	ck := w.conns[queueID]
	if IsNil(ck) {
		if err := w.ResetConnection(queueID); err != nil {
			time.Sleep(time.Minute)
			return fmt.Errorf("can not ck to clickhouse: %s", err)
		}
		ck = w.conns[queueID]
	}

	batch, err := ck.PrepareBatch(context.Background(), w.prepare)
	if err != nil {
		return err
	}

	ckdbBlock := &ckdb.Block{
		Batch: batch,
	}
	for _, item := range items {
		if err := item.WriteBlock(ckdbBlock); err != nil {
			return fmt.Errorf("item write block failed: %s", err)
		}
		ckdbBlock.ResetIndex()
	}
	err = ckdbBlock.Batch.Send()
	if err != nil {
		return fmt.Errorf("send write block failed: %s", err)
	} else {
		log.Debugf("batch write success, table (%s.%s) commit %d items", w.table.Database, w.table.LocalName, len(items))
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

	log.Infof("ckwriter %s closed", w.name)
}
