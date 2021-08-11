package ckmonitor

import (
	"fmt"
	"strings"
	"time"

	logging "github.com/op/go-logging"

	"database/sql"

	clickhouse "github.com/ClickHouse/clickhouse-go"
	"gitlab.yunshan.net/yunshan/droplet/config"
)

var log = logging.MustGetLogger("monitor")

const DFDiskPrefix = "path_" // clickhouse的config.xml配置文件中，deepflow命名的disk名称以‘path_’开头

type Monitor struct {
	checkInterval              int
	freeSpaceThreshold         int
	usedPercentThreshold       int
	primaryConn, secondaryConn *sql.DB
	primaryAddr, secondaryAddr string
	username, password         string
	exit                       bool
}

type DiskInfo struct {
	name, path                           string
	freeSpace, totalSpace, keepFreeSpace uint64
}

type Partition struct {
	partition, database, table string
	minTime, maxTime           time.Time
	rows, bytesOnDisk          uint64
}

func NewCKMonitor(cfg *config.CKDiskMonitor, primaryAddr, secondaryAddr, username, password string) (*Monitor, error) {
	m := &Monitor{
		checkInterval:        cfg.CheckInterval,
		usedPercentThreshold: cfg.UsedPercent,
		freeSpaceThreshold:   cfg.FreeSpace << 30, // GB
		primaryAddr:          primaryAddr,
		secondaryAddr:        secondaryAddr,
		username:             username,
		password:             password,
	}
	var err error
	m.primaryConn, err = newCKConnection(primaryAddr, username, password)
	if err != nil {
		return nil, err
	}

	if secondaryAddr != "" {
		m.secondaryConn, err = newCKConnection(secondaryAddr, username, password)
		if err != nil {
			return nil, err
		}
	}

	return m, nil
}

func newCKConnection(addr, username, password string) (*sql.DB, error) {
	connect, err := sql.Open("clickhouse", fmt.Sprintf("%s?username=%s&password=%s", addr, username, password))
	if err != nil {
		return nil, err
	}
	if err := connect.Ping(); err != nil {
		if exception, ok := err.(*clickhouse.Exception); ok {
			log.Warningf("[%d] %s \n%s\n", exception.Code, exception.Message, exception.StackTrace)
		}
		return nil, err
	}
	return connect, nil
}

func (m *Monitor) updateConnection(connect *sql.DB, addr string) *sql.DB {
	if addr == "" {
		return nil
	}

	if connect == nil || connect.Ping() != nil {
		if connect != nil {
			connect.Close()
		}
		connectNew, err := newCKConnection(addr, m.username, m.password)
		if err != nil {
			log.Warning(err)
		}
		return connectNew
	}
	return connect
}

// 如果clickhouse重启等，需要自动更新连接
func (m *Monitor) updateConnections() {
	m.primaryConn = m.updateConnection(m.primaryConn, m.primaryAddr)
	m.secondaryConn = m.updateConnection(m.secondaryConn, m.secondaryAddr)
}

func getDFMaxDiskNumInfo(connect *sql.DB) (*DiskInfo, error) {
	rows, err := connect.Query("SELECT name,path,free_space,total_space,keep_free_space FROM system.disks")
	if err != nil {
		return nil, err
	}
	// 找出名字为path_x中，x为最大时的disk,
	maxPathNum := -1
	var maxDiskInfo *DiskInfo
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
		// deepflow的数据, 写入path_*下
		if strings.HasPrefix(name, DFDiskPrefix) {
			var pathNum int
			fmt.Sscanf(name, DFDiskPrefix+"%d", &pathNum)
			if maxPathNum < pathNum {
				maxPathNum = pathNum
				maxDiskInfo = &DiskInfo{name, path, freeSpace, totalSpace, keepFreeSpace}
			}
		}
	}
	if maxDiskInfo == nil {
		return nil, fmt.Errorf("can not find any deepflow data disk like '%s'", DFDiskPrefix)
	}
	return maxDiskInfo, nil
}

func (m *Monitor) isDiskNeedClean(diskInfo *DiskInfo) bool {
	if diskInfo.totalSpace > 0 {
		usage := (diskInfo.totalSpace - diskInfo.freeSpace) * 100 / diskInfo.totalSpace
		if usage > uint64(m.usedPercentThreshold) {
			log.Warningf("disk usage is over %d, will do partition drop. disk name: %s, path: %s, total space: %d, free space: %d, usage: %d",
				m.usedPercentThreshold, diskInfo.name, diskInfo.path, diskInfo.totalSpace, diskInfo.freeSpace, usage)
			return true
		}
	}
	if diskInfo.totalSpace > uint64(m.freeSpaceThreshold) &&
		diskInfo.freeSpace < uint64(m.freeSpaceThreshold) {
		log.Warningf("free space is %d < %dG, will do partition drop. disk name: %s, path: %s, total space: %d, free space: %d",
			diskInfo.freeSpace, m.freeSpaceThreshold>>30, diskInfo.name, diskInfo.path, diskInfo.totalSpace, diskInfo.freeSpace)
		return true
	}
	return false
}

func getMinPartitions(connect *sql.DB) ([]Partition, error) {
	sql := fmt.Sprintf("SELECT min(partition),count(distinct partition),database,table,min(min_time),max(max_time),sum(rows),sum(bytes_on_disk) FROM system.parts WHERE disk_name LIKE '%s' and active=1 GROUP BY database,table ORDER BY database,table ASC",
		DFDiskPrefix+"%")
	rows, err := connect.Query(sql)
	if err != nil {
		return nil, err
	}
	partitions := []Partition{}
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
		// 只删除partition数量2个以上的partition中最小的一个
		if count > 1 {
			partitions = append(partitions, Partition{partition, database, table, minTime, maxTime, rowCount, bytesOnDisk})
		}
	}
	return partitions, nil
}

func (m *Monitor) dropMinPartitions(connect *sql.DB) error {
	partitions, err := getMinPartitions(connect)
	if err != nil {
		return err
	}

	for _, p := range partitions {
		sql := fmt.Sprintf("ALTER TABLE %s.%s DROP PARTITION '%s'", p.database, p.table, p.partition)
		log.Warningf("drop partition: %s, database: %s, table: %s, minTime: %s, maxTime: %s, rows: %d, bytesOnDisk: %d", p.partition, p.database, p.table, p.minTime, p.maxTime, p.rows, p.bytesOnDisk)
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
		for _, connect := range []*sql.DB{m.primaryConn, m.secondaryConn} {
			if connect == nil {
				continue
			}
			diskInfo, err := getDFMaxDiskNumInfo(connect)
			if err != nil {
				log.Warning(err)
				continue
			}
			if m.isDiskNeedClean(diskInfo) {
				err := m.dropMinPartitions(connect)
				if err != nil {
					log.Warning("drop partition failed.", err)
				}
			}
		}
	}
}

func (m *Monitor) Close() {
	m.exit = true
}
