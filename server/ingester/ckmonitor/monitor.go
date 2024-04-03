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
	"strings"
	"time"

	logging "github.com/op/go-logging"

	"database/sql"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
)

var log = logging.MustGetLogger("monitor")

type Monitor struct {
	cfg           *config.Config
	checkInterval int

	Conns              common.DBs
	Addrs              []string
	username, password string
	exit               bool
}

type DiskInfo struct {
	name, path                                      string
	freeSpace, totalSpace, keepFreeSpace, usedSpace uint64
}

type Partition struct {
	partition, database, table string
	minTime, maxTime           time.Time
	rows, bytesOnDisk          uint64
}

func NewCKMonitor(cfg *config.Config) (*Monitor, error) {
	m := &Monitor{
		cfg:           cfg,
		checkInterval: cfg.CKDiskMonitor.CheckInterval,
		Addrs:         cfg.CKDB.ActualAddrs,
		username:      cfg.CKDBAuth.Username,
		password:      cfg.CKDBAuth.Password,
	}
	var err error
	m.Conns, err = common.NewCKConnections(m.Addrs, m.username, m.password)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// 如果clickhouse重启等，需要自动更新连接
func (m *Monitor) updateConnections() {
	if len(m.Addrs) == 0 {
		return
	}

	var err error
	for i, connect := range m.Conns {
		if connect == nil || connect.Ping() != nil {
			if connect != nil {
				connect.Close()
			}
			m.Conns[i], err = common.NewCKConnection(m.Addrs[i], m.username, m.password)
			if err != nil {
				log.Warning(err)
			}
		}
	}
}

func (m *Monitor) getDiskInfos(connect *sql.DB) ([]*DiskInfo, error) {
	rows, err := connect.Query("SELECT name,path,free_space,total_space,keep_free_space FROM system.disks")
	if err != nil {
		return nil, err
	}

	diskInfos := []*DiskInfo{}
	for rows.Next() {
		var (
			name, path                           string
			freeSpace, totalSpace, keepFreeSpace uint64
		)
		err := rows.Scan(&name, &path, &freeSpace, &totalSpace, &keepFreeSpace)
		if err != nil {
			return nil, nil
		}
		log.Debugf("name: %s, path: %s, freeSpace: %d, totalSpace: %d, keepFreeSpace: %d", name, path, freeSpace, totalSpace, keepFreeSpace)
		for _, cleans := range m.cfg.CKDiskMonitor.DiskCleanups {
			diskPrefix := cleans.DiskNamePrefix
			if strings.HasPrefix(name, diskPrefix) {
				usedSpace := totalSpace - freeSpace
				diskInfos = append(diskInfos, &DiskInfo{name, path, freeSpace, totalSpace, keepFreeSpace, usedSpace})
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
		if database == priorityDrop.Database {
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
	sql := fmt.Sprintf("SELECT min(partition),count(distinct partition),database,table,min(min_time),max(max_time),sum(rows),sum(bytes_on_disk) FROM system.parts WHERE disk_name='%s' and active=1 GROUP BY database,table ORDER BY database,table ASC",
		diskInfo.name)
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
		)
		err := rows.Scan(&partition, &count, &database, &table, &minTime, &maxTime, &rowCount, &bytesOnDisk)
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
		sql := fmt.Sprintf("ALTER TABLE %s.`%s` DROP PARTITION '%s'", p.database, p.table, p.partition)
		log.Warningf("drop partition: %s, database: %s, table: %s, minTime: %s, maxTime: %s, rows: %d, bytesOnDisk: %d", p.partition, p.database, p.table, p.minTime, p.maxTime, p.rows, p.bytesOnDisk)
		_, err := connect.Exec(sql)
		if err != nil {
			return err
		}
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
		}
	}
}

func (m *Monitor) Close() error {
	m.exit = true
	return nil
}
