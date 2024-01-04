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

package store

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/influxdata/influxdb/client/v2"

	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	CONFIDENCE_DB                 = "_tsdb_meta"
	CONFIDENCE_MEASUREMENT        = "confidence"
	CONFIDENCE_MEASUREMENT_SYNCED = "confidence_synced"
	TAG_DB                        = "db"
	TAG_ID                        = "_id"
	TAG_MEASUREMENT               = "table"
	FIELD_STATUS                  = "status"

	SYNC_COUNT_ONCE         = 200  // 每次获取多少条记录进行同步
	SYNC_INTERVAL           = 60   // 两次同步间隔时间 单位:秒
	SYNC_START_DELAY        = 300  // 同步HB的开始时间相对当前时间的时延
	SYNC_FAILED_RETRY_TIMES = 3    // 同步失败，重试次数,
	MAX_BATCH_WRITE_POINTS  = 1024 // 批量写influxdb的数量
	RP_1S                   = "rp_1s"
	RP_1M                   = "rp_1m"
	DURATION_1S             = "1d" // 自动同步创建的db的RP默认值
	SHARD_DURATION_1S       = "2h"
	DURATION_1M             = "10d" // 自动同步创建的db的RP默认值
	SHARD_DURATION_1M       = "1d"
	DURATION_10M            = "100d"
	SHARD_DURATION_10M      = "10d"
)

type RepairStatus uint8

const (
	PRIMARY_FAILED            RepairStatus = iota // 主写失败，不同步
	SYNC_SUCCESS                                  // 同步成功
	REPLICA_DISCONNECT                            // 备influxdb无法连接，等待连接成功后, 再尝试同步
	SYNC_FAILED_1                                 // 备同步失败1次
	SYNC_FAILED_2                                 // 备同步失败2次
	SYNC_FAILED_3                                 // 备同步3次失败，不再同步
	SYNC_FAILED_SERIES_EXCEED                     // 备series数量超过限制, 同步失败, 不再同步

	STATUS_INVALID
)

type Repair struct {
	wg    sync.WaitGroup
	start bool //启动标识

	shardID       string
	primaryClient client.Client
	replicaClient client.Client

	rp              string // 同步的retention policy名, 目前只支持名为"autogen", "m10"
	syncStartDelay  int    // 同步confidence的开始时间相对当前时间的时延，默认是 300 秒
	syncInterval    int    // 默认是 60秒
	syncCountOnce   int    // 默认 200
	syncDBRange     string // 同步的database范围，防止zero和roze同时同步同一组数据
	repairCondition string

	replicaDBs map[string]bool // 标识是否有数据库，没有的话，需要创建
	counter    CounterRepair
	utils.Closable
}

type CounterRepair struct {
	SyncCount int64 `statsd:"sync-count"`
}

func NewRepair(addrPrimary, addrReplica, httpUsername, httpPassword, rp, shardID, dbRegex string, start bool, syncStartDelay, syncInterval, syncCountOnce int) (*Repair, error) {
	if addrReplica == "" {
		log.Info("Replica influxdb is not set， skip repair")
		start = false
	}

	if !start {
		log.Infof("Repair not start. Primary: %s, Replica: %s, rp: %s, shardId %s, StartDelay %d, Interval %d, SyncCountOnce %d",
			addrPrimary, addrReplica, rp, shardID, syncStartDelay, syncInterval, syncCountOnce)
		return &Repair{start: false}, nil
	}

	if rp != RP_1S && rp != RP_1M {
		str := fmt.Sprintf("rp '%s' is not support, only support rp(%s, %s)", rp, RP_1S, RP_1M)
		log.Error(str)
		return nil, fmt.Errorf(str)
	}

	syncDBRange := ""
	if dbRegex != "" {
		syncDBRange = " and db=~/" + dbRegex + "/"
	}

	primaryClient, err := client.NewHTTPClient(client.HTTPConfig{
		Addr:     addrPrimary,
		Username: httpUsername,
		Password: httpPassword,
	})
	if err != nil {
		log.Error("create influxdb http client failed:", addrPrimary)
		return nil, err
	}
	log.Infof("new influxdb primary client addr(%s)", addrPrimary)

	replicaClient, err := client.NewHTTPClient(client.HTTPConfig{
		Addr:     addrReplica,
		Username: httpUsername,
		Password: httpPassword,
	})
	if err != nil {
		log.Error("create influxdb http client failed:", addrReplica)
		return nil, err
	}
	log.Infof("new influxdb replica client addr(%s)", addrReplica)

	if syncStartDelay <= 60 {
		syncStartDelay = SYNC_START_DELAY
	}

	if syncInterval <= 10 {
		syncInterval = SYNC_INTERVAL
	}

	if syncCountOnce <= 0 {
		syncCountOnce = SYNC_COUNT_ONCE
	}

	log.Infof("New repair success. Primary: %s, Replica: %s, rp: %s, shardId %s, StartDelay %d, Interval %d, SyncCountOnce %d syncDBRange %s",
		addrPrimary, addrReplica, rp, shardID, syncStartDelay, syncInterval, syncCountOnce, syncDBRange)
	return &Repair{
		shardID:        shardID,
		primaryClient:  primaryClient,
		replicaClient:  replicaClient,
		rp:             rp,
		start:          start,
		syncStartDelay: syncStartDelay,
		syncInterval:   syncInterval,
		syncCountOnce:  syncCountOnce,
		syncDBRange:    syncDBRange,
		replicaDBs:     make(map[string]bool),
	}, nil
}

func (r *Repair) Run() {
	if !r.start {
		return
	}
	stats.RegisterCountable("repair", r,
		stats.OptionStatTags{"rp": r.rp},
		stats.OptionStatTags{"shard_id": r.shardID})
	go r.run()
}

func (r *Repair) Close() {
	if !r.start {
		return
	}
	r.start = false
	r.wg.Wait()
	r.primaryClient.Close()
	r.replicaClient.Close()
	log.Infof("repair(rp: %s shardID: %s) closed", r.rp, r.shardID)
}

func (r *Repair) checkConnectionsOK() bool {
	if _, _, err := r.primaryClient.Ping(0); err != nil {
		log.Errorf("http connect to primaryClient failed: %s", err)
		return false
	}
	if _, _, err := r.replicaClient.Ping(0); err != nil {
		log.Errorf("http connect to replicaClient failed: %s", err)
		return false
	}
	return true
}

func isStatusNeedRepair(status RepairStatus) bool {
	switch status {
	case PRIMARY_FAILED, SYNC_SUCCESS, SYNC_FAILED_3, SYNC_FAILED_SERIES_EXCEED:
		return false
	case REPLICA_DISCONNECT, SYNC_FAILED_1, SYNC_FAILED_2:
		return true
	default:
		log.Warning("invalid status: %d", status)
	}
	return false
}

func (r *Repair) getRepairCondition() string {
	if r.repairCondition != "" {
		return r.repairCondition
	}
	str := []string{}
	for i := 0; i < int(STATUS_INVALID); i++ {
		if isStatusNeedRepair(RepairStatus(i)) {
			str = append(str, fmt.Sprintf("%s=%d", FIELD_STATUS, i))
		}
	}
	r.repairCondition = "(" + strings.Join(str, " or ") + ")" + r.syncDBRange
	return r.repairCondition
}

func (r *Repair) getConfidences() ([]Confidence, error) {
	startTime := time.Duration(time.Now().UnixNano()) - time.Duration(r.syncStartDelay)*time.Second
	cmd := fmt.Sprintf("select * from %s where time <%d and %s='%s' and (%s) order by time desc limit %d",
		CONFIDENCE_MEASUREMENT, startTime, TAG_ID, r.shardID, r.getRepairCondition(), r.syncCountOnce)
	rows, err := queryRows(r.primaryClient, CONFIDENCE_DB, r.rp, cmd)
	if err != nil {
		log.Errorf("primaryClient query cmd(%s) failed: %s", cmd, err)
		return nil, err
	}

	confidences := make([]Confidence, 0)
	for _, row := range rows {
		var dbIndex, shardIDIndex, measurementIndex, statusIndex int
		for i, columnName := range row.Columns {
			switch columnName {
			case TAG_DB:
				dbIndex = i
			case TAG_ID:
				shardIDIndex = i
			case TAG_MEASUREMENT:
				measurementIndex = i
			case FIELD_STATUS:
				statusIndex = i
			}
		}

		if dbIndex == 0 || shardIDIndex == 0 || measurementIndex == 0 || statusIndex == 0 {
			return nil, fmt.Errorf("get confidence failed: can not get '%s' or '%s' or '%s' or '%s' values, key index is (%d, %d, %d, %d), 0 is invalid ",
				TAG_DB, TAG_ID, TAG_MEASUREMENT, FIELD_STATUS, dbIndex, shardIDIndex, measurementIndex, statusIndex)
		}

		for _, v := range row.Values {
			if v[dbIndex] == nil || v[measurementIndex] == nil || v[0] == nil || v[statusIndex] == nil || v[shardIDIndex] == nil {
				log.Warningf("confidence value is nil: %v %v %v %v %v", v[dbIndex], v[measurementIndex], v[0], v[statusIndex], v[shardIDIndex])
				continue
			}
			confidences = append(confidences, Confidence{
				db:          v[dbIndex].(string),
				measurement: v[measurementIndex].(string),
				shardID:     v[shardIDIndex].(string),
				timestamp:   unmarshalInt64(v[0]),
				status:      RepairStatus(unmarshalInt64(v[statusIndex])),
			})
		}
	}
	return confidences, nil
}

func (r *Repair) syncConfidenceData() {
	confidences, err := r.getConfidences()
	if err != nil {
		log.Error(err)
		return
	}
	isSyncSuccess := make([]bool, len(confidences))
	for i, c := range confidences {
		r.checkCreateDatabase(r.replicaClient, r.primaryClient, c.db)
		syncCount, err := syncData(c.timestamp, c.db, c.measurement, r.rp, r.primaryClient, r.replicaClient)
		if err == nil {
			r.counter.SyncCount += int64(syncCount)
			isSyncSuccess[i] = true
		} else {
			log.Errorf("sync failed: timestamp=%d db=%s Measurement=%s shardID=%s", c.timestamp, c.db, c.measurement, c.shardID)
			isSyncSuccess[i] = false

		}
	}
	r.updateConfidences(confidences, isSyncSuccess)
	return
}

func (r *Repair) updateConfidences(confidences []Confidence, isSyncSuccess []bool) {
	confidenceBP, _ := client.NewBatchPoints(client.BatchPointsConfig{
		Database:        CONFIDENCE_DB,
		Precision:       INFLUXDB_PRECISION_S,
		RetentionPolicy: r.rp,
	})

	tags := make(map[string]string)
	fields := make(map[string]interface{})
	for i, c := range confidences {
		tags[TAG_DB] = c.db
		tags[TAG_MEASUREMENT] = c.measurement
		tags[TAG_ID] = c.shardID

		status := c.status
		if isSyncSuccess[i] {
			status = SYNC_SUCCESS
		} else {
			switch c.status {
			case REPLICA_DISCONNECT:
				status = SYNC_FAILED_1
			case SYNC_FAILED_1:
				status = SYNC_FAILED_2
			case SYNC_FAILED_2:
				status = SYNC_FAILED_3
			default:
				log.Error("confidences %v status is %d unknown", c, c.status)
				continue
			}
		}
		fields[FIELD_STATUS] = int64(status)

		measurement := CONFIDENCE_MEASUREMENT
		if !isStatusNeedRepair(status) {
			//  同步完成的，需要删除，并移入CONFIDENCE_SYNCED表
			r.deleteConfidence(&c)
			measurement = CONFIDENCE_MEASUREMENT_SYNCED
		}
		if pt, err := client.NewPoint(measurement, tags, fields, time.Unix(0, c.timestamp)); err == nil {
			confidenceBP.AddPoint(pt)
		} else {
			log.Warning("new NewPoint failed:", err)
		}
	}

	if len(confidenceBP.Points()) > 0 {
		if err := r.primaryClient.Write(confidenceBP); err != nil {
			log.Errorf("httpclient  db(%s) write batch point failed: %s", CONFIDENCE_DB, err)
		}
	}
}

func (r *Repair) deleteConfidence(c *Confidence) error {
	cmd := fmt.Sprintf("delete from %s where time=%d and %s='%s' and %s='%s' and %s='%s'",
		CONFIDENCE_MEASUREMENT, c.timestamp,
		TAG_DB, c.db,
		TAG_MEASUREMENT, c.measurement,
		TAG_ID, c.shardID)

	_, err := queryResponse(r.primaryClient, CONFIDENCE_DB, r.rp, cmd)
	if err != nil {
		log.Warningf("delete confidence cmd(%s) failed: %s", cmd, err)
		return err
	}
	log.Debug("delete confidence cmd:", cmd)
	return nil
}

func (r *Repair) checkCreateDatabase(client, clientRP client.Client, dbname string) {
	if len(r.replicaDBs) == 0 {
		rows, err := queryRows(client, "", r.rp, "show databases")
		if err == nil && len(rows) > 0 {
			for _, col := range rows[0].Values {
				if name, ok := col[0].(string); ok {
					r.replicaDBs[name] = true
				}
			}
		}
	}

	if _, ok := r.replicaDBs[dbname]; ok {
		return
	}

	log.Infof("database %s is not exist, create database now.", dbname)
	_, err := queryResponse(client, "", r.rp, fmt.Sprintf("create database %s", dbname))
	if err != nil {
		log.Warningf("Create database %s failed", dbname)
		return
	} else {
		r.replicaDBs[dbname] = true
	}

	rp := getRetentionPolicy(clientRP, dbname, r.rp)

	if rp == nil {
		switch r.rp {
		case RP_1S:
			rp = &RetentionPolicy{
				name:          r.rp,
				duration:      DURATION_1S,
				shardDuration: SHARD_DURATION_1S,
				defaultFlag:   false,
			}
		case RP_1M:
			rp = &RetentionPolicy{
				name:          r.rp,
				duration:      DURATION_1M,
				shardDuration: SHARD_DURATION_1M,
				defaultFlag:   true,
			}
		default:
			log.Errorf("not support the retention policy %s", r.rp)
			return
		}
	}

	checkCreateRP(client, dbname, rp)
}

func (r *Repair) run() {
	r.wg.Add(1)
	ticker := time.NewTicker(time.Second)
	tickCounter := 0
	defer ticker.Stop()
	defer r.wg.Done()
	for {
		select {
		case <-ticker.C:
			if !r.start {
				return
			}
			tickCounter++
			if tickCounter < r.syncInterval {
				continue
			}
			tickCounter = 0
			if !r.checkConnectionsOK() {
				continue
			}
			r.syncConfidenceData()
		}
	}
}

func (r *Repair) GetCounter() interface{} {
	counter := r.counter

	r.counter.SyncCount = 0

	return &counter
}
