/*
 * Copyright (c) 2023 Yunshan Networks
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
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func getFullTable(database, table string) string {
	return fmt.Sprintf("%s.`%s`", database, table)
}

func getDfStorageTTLsMap(connect *sql.DB) (map[string]int, error) {
	ttlMap := make(map[string]int)

	sql := "SELECT database,table,engine_full FROM system.tables WHERE storage_policy='df_storage'"
	log.Info(sql)
	rows, err := connect.Query(sql)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`TTL time \+ toIntervalHour\((\d+)\)`)
	for rows.Next() {
		var database, table, engine_full string
		err := rows.Scan(&database, &table, &engine_full)
		if err != nil {
			return nil, err
		}
		// find first match
		matches := re.FindAllStringSubmatch(engine_full, 1)
		for _, match := range matches {
			hourInterval, err := strconv.Atoi(match[1])
			if err != nil || hourInterval == 0 {
				log.Warningf("engine full (%s) not match ttl hour", engine_full)
				break
			}
			ttlMap[getFullTable(database, table)] = hourInterval
			break
		}
	}
	return ttlMap, nil
}

func getPartitionsMap(connect *sql.DB) (map[string][]string, error) {
	sql := "SELECT partition,database,table FROM system.parts WHERE active=1 GROUP BY partition,database,table ORDER BY partition"
	rows, err := connect.Query(sql)
	log.Info(sql)
	if err != nil {
		return nil, err
	}

	partitionsMap := make(map[string][]string)
	for rows.Next() {
		var partition, database, table string

		err := rows.Scan(&partition, &database, &table)
		if err != nil {
			return nil, err
		}
		fullTable := getFullTable(database, table)
		partitions := partitionsMap[fullTable]
		if len(partitions) == 0 {
			partitionsMap[fullTable] = []string{partition}
		} else {
			partitions = append(partitions, partition)
			partitionsMap[fullTable] = partitions
		}
	}
	return partitionsMap, nil
}

func isPartitionExpired(partition string, ttlHour int) bool {
	layout := "2006-01-02 15:04:05"
	partitionTime, err := time.Parse(layout, partition)
	if err != nil {
		log.Warningf("parse time failed: %s", err)
		return false
	}
	// expired more then 1 day, then clear
	return time.Since(partitionTime) > time.Duration(ttlHour)*time.Hour+time.Hour*24
}

func dropPartiton(connect *sql.DB, partition, fullTable string) error {
	sql := fmt.Sprintf("ALTER TABLE %s DROP PARTITION '%s'", fullTable, partition)
	log.Info("drop partition for TTL expired: ", sql)
	_, err := connect.Exec(sql)
	if err != nil {
		return err
	}

	return nil
}

func (m *Monitor) checkAndDropExpiredPartition(connect *sql.DB) error {
	ttlsMap, err := getDfStorageTTLsMap(connect)
	if err != nil {
		log.Warningf("get ttlsMap failed: %s", err)
		return err
	}
	partitionsMap, err := getPartitionsMap(connect)
	if err != nil {
		log.Warningf("get partitionsMap failed: %s", err)
		return err
	}

	for fullTable, partitions := range partitionsMap {
		ttlHour, ok := ttlsMap[fullTable]
		if !ok {
			continue
		}
		for _, partition := range partitions {
			if isPartitionExpired(partition, ttlHour) {
				log.Infof("partition (%s) of %s TTL is %d hour is expired", partition, fullTable, ttlHour)
				if err := dropPartiton(connect, partition, fullTable); err != nil {
					log.Warningf("%s drop partition %s failed: %s", fullTable, partition, err)
					continue
				}
				parts := strings.Split(fullTable, ".`")
				if len(parts) >= 2 {
					m.sendStatsTTLExpiredDeleteData(parts[0], strings.TrimRight(parts[1], "`"), partition)
				}
			}
		}
	}
	return nil
}
