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

package ckmonitor

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	logging "github.com/op/go-logging"

	"database/sql"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/stats/pb"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var log = logging.MustGetLogger("monitor")

const (
	CLICKHOUSE_TABLE_PARTS_NAME = "parts"
	BYCONITY_TABLE_PARTS_NAME   = "cnch_parts"
	BYCONITY_DISK_TYPE_HDFS     = "bytehdfs"
	BYCONITY_DISK_TYPE_S3       = "bytes3"
)

type Monitor struct {
	cfg           *config.Config
	checkInterval int

	Conns              common.DBs
	ckdbType           string
	Addrs              *[]string
	CurrentAddrs       []string
	username, password string
	tablePartsName     string
	storagePolicy      string
	exit               bool

	statsClient  *stats.UDPClient
	statsEncoder *codec.SimpleEncoder
}

type DiskInfo struct {
	name, path, diskType                            string
	freeSpace, totalSpace, keepFreeSpace, usedSpace uint64
}

type Partition struct {
	partition, database, table string
	minTime, maxTime           time.Time
	rows, bytesOnDisk          uint64
}

func NewCKMonitor(cfg *config.Config) (*Monitor, error) {
	tablePartsName := CLICKHOUSE_TABLE_PARTS_NAME
	ckdbType := cfg.CKDB.Type
	if ckdbType == ckdb.CKDBTypeByconity {
		tablePartsName = BYCONITY_TABLE_PARTS_NAME
	}
	m := &Monitor{
		cfg:            cfg,
		checkInterval:  cfg.CKDiskMonitor.CheckInterval,
		ckdbType:       ckdbType,
		Addrs:          cfg.CKDB.ActualAddrs,
		CurrentAddrs:   utils.CloneStringSlice(*cfg.CKDB.ActualAddrs),
		username:       cfg.CKDBAuth.Username,
		password:       cfg.CKDBAuth.Password,
		tablePartsName: tablePartsName,
		storagePolicy:  cfg.CKDB.StoragePolicy,
		statsEncoder:   &codec.SimpleEncoder{},
	}
	statsClient, err := stats.NewUDPClient(
		stats.UDPConfig{
			Addr:        stats.GetDFRemote(),
			PayloadSize: 1400},
	)
	if err != nil {
		return nil, err
	}
	m.statsClient = statsClient

	return m, nil
}

func (m *Monitor) sendStatsForceDeleteData(db, table, partition string, bytesOnDisk, rows uint64) {
	m.sendStats("deepflow_server_ingester_force_delete_clickhouse_data", db, table, partition, bytesOnDisk, rows)
}

func (m *Monitor) sendStatsTTLExpiredDeleteData(db, table, partition string) {
	m.sendStats("deepflow_server_ingester_ttl_expired_delete_clickhouse_data", db, table, partition, 0, 0)
}

func (m *Monitor) sendStats(name, db, table, partition string, bytesOnDisk, rows uint64) {
	dfStats := &pb.Stats{
		Name:               name,
		Timestamp:          uint64(time.Now().Unix()),
		TagNames:           make([]string, 0, 4),
		TagValues:          make([]string, 0, 4),
		MetricsFloatNames:  make([]string, 0, 2),
		MetricsFloatValues: make([]float64, 0, 2),
	}
	dfStats.TagNames = append(dfStats.TagNames, "host", "db", "table", "partition")
	dfStats.TagValues = append(dfStats.TagValues, stats.GetHostname(), db, table, partition)
	dfStats.MetricsFloatNames = append(dfStats.MetricsFloatNames, "bytes_on_disk", "rows")
	dfStats.MetricsFloatValues = append(dfStats.MetricsFloatValues, float64(bytesOnDisk), float64(rows))

	m.statsEncoder.Reset()
	dfStats.Encode(m.statsEncoder)
	m.statsClient.Write(m.statsEncoder.Bytes())
}

// 如果clickhouse重启等，需要自动更新连接
func (m *Monitor) updateConnections() {
	if len(*m.Addrs) == 0 {
		return
	}
	if len(m.Conns) == 0 || !reflect.DeepEqual(m.CurrentAddrs, *m.Addrs) {
		log.Infof("clickhouse endponts change from %v to %v", m.CurrentAddrs, *m.Addrs)
		m.CurrentAddrs = utils.CloneStringSlice(*m.Addrs)
		for _, connect := range m.Conns {
			if connect != nil {
				connect.Close()
			}
		}

		m.Conns = m.Conns[:0]
		for _, addr := range m.CurrentAddrs {
			conns, err := common.NewCKConnection(addr, m.username, m.password)
			if err != nil {
				log.Warning(err)
			}
			m.Conns = append(m.Conns, conns)
		}
	}

	var err error
	for i, connect := range m.Conns {
		if connect == nil || connect.Ping() != nil {
			if connect != nil {
				connect.Close()
			}
			m.Conns[i], err = common.NewCKConnection(m.CurrentAddrs[i], m.username, m.password)
			if err != nil {
				log.Warning(err)
			}
		}
	}
}

func (m *Monitor) getDiskInfos(connect *sql.DB) ([]*DiskInfo, error) {
	rows, err := connect.Query("SELECT name,path,type,free_space,total_space,keep_free_space FROM system.disks")
	if err != nil {
		return nil, err
	}

	diskInfos := []*DiskInfo{}
	for rows.Next() {
		var (
			name, path, diskType                 string
			freeSpace, totalSpace, keepFreeSpace uint64
		)
		err := rows.Scan(&name, &path, &diskType, &freeSpace, &totalSpace, &keepFreeSpace)
		if err != nil {
			return nil, nil
		}
		log.Debugf("name: %s, path: %s, type: %s, freeSpace: %d, totalSpace: %d, keepFreeSpace: %d", name, path, diskType, freeSpace, totalSpace, keepFreeSpace)
		for _, cleans := range m.cfg.CKDiskMonitor.DiskCleanups {
			diskPrefix := cleans.DiskNamePrefix
			if strings.HasPrefix(name, diskPrefix) {
				usedSpace := totalSpace - freeSpace
				diskInfos = append(diskInfos, &DiskInfo{name, path, diskType, freeSpace, totalSpace, keepFreeSpace, usedSpace})
			}
		}
	}
	if len(diskInfos) == 0 {
		diskPrefixs := ""
		for _, cleans := range m.cfg.CKDiskMonitor.DiskCleanups {
			diskPrefixs += cleans.DiskNamePrefix + ","
		}
		return nil, fmt.Errorf("can not find any deepflow data disk like '%s'", diskPrefixs)
	}
	return diskInfos, nil
}

func (m *Monitor) getDiskCleanupConfig(diskName string) *config.DiskCleanup {
	for i, c := range m.cfg.CKDiskMonitor.DiskCleanups {
		if strings.HasPrefix(diskName, c.DiskNamePrefix) {
			return &m.cfg.CKDiskMonitor.DiskCleanups[i]
		}
	}
	return nil
}

func (m *Monitor) isDiskNeedClean(diskInfo *DiskInfo) bool {
	if diskInfo.totalSpace == 0 {
		return false
	}
	cleanCfg := m.getDiskCleanupConfig(diskInfo.name)
	if cleanCfg == nil {
		return false
	}

	usage := (diskInfo.usedSpace*100 + diskInfo.totalSpace - 1) / diskInfo.totalSpace
	if usage > uint64(cleanCfg.UsedPercent) && diskInfo.freeSpace < uint64(cleanCfg.FreeSpace)<<30 {
		log.Infof("disk usage is over %d. disk name: %s, path: %s, total space: %d, free space: %d, usage: %d",
			cleanCfg.UsedPercent, diskInfo.name, diskInfo.path, diskInfo.totalSpace, diskInfo.freeSpace, usage)
		return true
	} else if cleanCfg.UsedSpace > 0 && diskInfo.usedSpace >= uint64(cleanCfg.UsedSpace)<<30 {
		log.Infof("disk used space is over %dG, disk name: %s, path: %s, total space: %d, free space: %d, usage: %d, usedSpace: %d.",
			cleanCfg.UsedSpace, diskInfo.name, diskInfo.path, diskInfo.totalSpace, diskInfo.freeSpace, usage, diskInfo.usedSpace)
		return true
	}
	return false
}

// 当所有磁盘都要满足清理条件时，才清理数据
func (m *Monitor) isDisksNeedClean(diskInfo *DiskInfo) bool {
	if !m.isDiskNeedClean(diskInfo) {
		return false
	}
	log.Warningf("disk free space is not enough, will do drop or move partitions.")
	return true
}

func (m *Monitor) isPriorityDrop(database, table string) bool {
	for _, priorityDrop := range m.cfg.CKDiskMonitor.PriorityDrops {
		if database == priorityDrop.Database ||
			// this database under all organizations needs to be cleaned
			(len(database) > ckdb.ORG_ID_PREFIX_LEN && (database[ckdb.ORG_ID_PREFIX_LEN:] == priorityDrop.Database)) {
			if priorityDrop.TablesContain == "" {
				return true
			}
			if strings.Contains(table, priorityDrop.TablesContain) {
				return true
			}
		}
	}
	return false
}

func (m *Monitor) getMinPartitions(connect *sql.DB, diskInfo *DiskInfo) ([]Partition, error) {
	sql := fmt.Sprintf("SELECT min(partition),count(distinct partition),database,table,min(min_time),max(max_time),argMin(rows,partition),argMin(bytes_on_disk,partition) FROM system.parts WHERE disk_name='%s' and active=1 GROUP BY database,table ORDER BY database,table ASC",
		diskInfo.name)
	if diskInfo.diskType == BYCONITY_DISK_TYPE_HDFS || diskInfo.diskType == BYCONITY_DISK_TYPE_S3 {
		sql = fmt.Sprintf("SELECT min(partition),count(distinct partition),database,table,argMin(rows,partition),argMin(bytes_on_disk,partition) FROM system.%s WHERE active=1 GROUP BY database,table ORDER BY database,table ASC",
			m.tablePartsName)
	}
	rows, err := connect.Query(sql)
	if err != nil {
		return nil, err
	}
	partitions, partitionsPriorityDrop := []Partition{}, []Partition{}
	for rows.Next() {
		var (
			partition, database, table   string
			minTime, maxTime             time.Time
			rowCount, bytesOnDisk, count uint64
			err                          error
		)

		if diskInfo.diskType == BYCONITY_DISK_TYPE_HDFS || diskInfo.diskType == BYCONITY_DISK_TYPE_S3 {
			err = rows.Scan(&partition, &count, &database, &table, &rowCount, &bytesOnDisk)
		} else {
			err = rows.Scan(&partition, &count, &database, &table, &minTime, &maxTime, &rowCount, &bytesOnDisk)
		}
		if err != nil {
			return nil, err
		}
		log.Debugf("partition: %s, count: %d, database: %s, table: %s, minTime: %s, maxTime: %s, rows: %d, bytesOnDisk: %d", partition, count, database, table, minTime, maxTime, rowCount, bytesOnDisk)
		minPartition := Partition{partition, database, table, minTime, maxTime, rowCount, bytesOnDisk}
		// 只删除partition数量2个以上的
		if count < 2 {
			continue
		}
		if m.isPriorityDrop(database, table) {
			partitionsPriorityDrop = append(partitionsPriorityDrop, minPartition)
		}
		partitions = append(partitions, minPartition)
	}
	if len(partitionsPriorityDrop) > 0 {
		return partitionsPriorityDrop, nil
	}
	return partitions, nil
}

func (m *Monitor) dropMinPartitions(connect *sql.DB, diskInfo *DiskInfo) error {
	partitions, err := m.getMinPartitions(connect, diskInfo)
	if err != nil {
		return err
	}

	for _, p := range partitions {
		// some partition names in ByConity have extra ' symbols
		partition := strings.Trim(p.partition, "'")
		sql := fmt.Sprintf("ALTER TABLE %s.`%s` DROP PARTITION '%s'", p.database, p.table, partition)
		log.Warningf("drop partition: %s, database: %s, table: %s, minTime: %s, maxTime: %s, rows: %d, bytesOnDisk: %d", p.partition, p.database, p.table, p.minTime, p.maxTime, p.rows, p.bytesOnDisk)
		_, err := connect.Exec(sql)
		if err != nil {
			log.Warningf("drop partiton: %s, database: %s, table: %s failed: %s", p.partition, p.database, p.table, err)
			continue
		}
		m.sendStatsForceDeleteData(p.database, p.table, p.partition, p.bytesOnDisk, p.rows)
	}
	return nil
}

func (m *Monitor) moveMinPartitions(connect *sql.DB, diskInfo *DiskInfo) error {
	partitions, err := m.getMinPartitions(connect, diskInfo)
	if err != nil {
		return err
	}
	for _, p := range partitions {
		sql := fmt.Sprintf("ALTER TABLE %s.`%s` MOVE PARTITION '%s' TO %s '%s'", p.database, p.table, p.partition, m.cfg.ColdStorage.ColdDisk.Type, m.cfg.ColdStorage.ColdDisk.Name)
		log.Warningf("move partition: %s, database: %s, table: %s, minTime: %s, maxTime: %s, rows: %d, bytesOnDisk: %d", p.partition, p.database, p.table, p.minTime, p.maxTime, p.rows, p.bytesOnDisk)
		_, err := connect.Exec(sql)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Monitor) Start() {
	go m.start()
}

func (m *Monitor) start() {
	counter := 0
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for !m.exit {
		<-ticker.C
		counter++
		if counter%m.checkInterval != 0 {
			continue
		}

		m.updateConnections()
		for _, connect := range m.Conns {
			if connect == nil {
				continue
			}
			diskInfos, err := m.getDiskInfos(connect)
			if err != nil {
				log.Warning(err)
				continue
			}
			for _, diskInfo := range diskInfos {
				if m.isDisksNeedClean(diskInfo) {
					if err := m.dropMinPartitions(connect, diskInfo); err != nil {
						log.Warning("drop partition failed.", err)
					}
				}
			}

			// the frequency of TTL check is 1/16 of disk check
			if counter%(m.checkInterval<<4) == 0 && !m.cfg.CKDiskMonitor.TTLCheckDisabled {
				m.checkAndDropExpiredPartition(connect)
			}
		}
	}
}

func (m *Monitor) Close() error {
	m.exit = true
	return nil
}
