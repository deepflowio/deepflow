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

package tagrecorder

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	mapset "github.com/deckarep/golang-set"

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/clickhouse"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
)

func (c *TagRecorder) UpdateChDictionary() {
	log.Info("tagrecorder update ch dictionary")
	var analyzers []mysql.Analyzer
	var controllers []mysql.Controller
	var azControllerConnections []mysql.AZControllerConnection
	var azAnalyzerConnections []mysql.AZAnalyzerConnection
	mysql.Db.Find(&analyzers)
	mysql.Db.Where("node_type = ?", common.CONTROLLER_NODE_TYPE_MASTER).Find(&controllers)
	mysql.Db.Find(&azControllerConnections)
	mysql.Db.Find(&azAnalyzerConnections)
	var masterRegion string
	var masterRegionPrefix string
	controllerIPToRegion := make(map[string]string)
	for _, azControllerConnection := range azControllerConnections {
		controllerIPToRegion[azControllerConnection.ControllerIP] = azControllerConnection.Region
	}
	for _, controller := range controllers {
		if region, ok := controllerIPToRegion[controller.IP]; ok {
			masterRegion = region
			masterRegionPrefix = controller.RegionDomainPrefix
			break
		}
	}
	if masterRegion == "" {
		log.Error("master region not found")
		return
	}
	analyzerIPToRegion := make(map[string]string)
	for _, azAnalyzerConnection := range azAnalyzerConnections {
		analyzerIPToRegion[azAnalyzerConnection.AnalyzerIP] = azAnalyzerConnection.Region
	}
	connectMaster, err := clickhouse.Connect(c.cfg.ClickHouseCfg)
	if err != nil {
		log.Error(err)
		return
	}
	var clusters []clickhouse.Clusters
	if err := connectMaster.Select(&clusters, "select host_address,port from system.clusters"); err != nil {
		log.Error(err)
		connectMaster.Close()
		return
	}
	connectMaster.Close()
	// 遍历本区域所有数据节点检查并更新字典定义
	for _, cluster := range clusters {
		nodeIP := os.Getenv(common.NODE_IP_KEY)
		analyzerRegion, ok := analyzerIPToRegion[nodeIP]
		if !ok {
			continue
		}
		replicaSQL := ""
		if analyzerRegion == masterRegion {
			replicaSQL = fmt.Sprintf("REPLICA (HOST '%s' PRIORITY %s)", c.cfg.MySqlCfg.Host, "1")
		} else {
			replicaSQL = fmt.Sprintf("REPLICA (HOST '%s%s' PRIORITY %s)", masterRegionPrefix, c.cfg.MySqlCfg.Host, "1")
		}
		c.cfg.ClickHouseCfg.Host = cluster.HostAddress
		c.cfg.ClickHouseCfg.Port = uint32(cluster.Port)
		connect, err := clickhouse.Connect(c.cfg.ClickHouseCfg)
		if err != nil {
			continue
		}
		log.Infof("refresh clickhouse dictionary in (%s: %d)", cluster.HostAddress, c.cfg.ClickHouseCfg.Port)
		var databases []string

		// 检查并创建数据库
		if err := connect.Select(&databases, "SHOW DATABASES"); err != nil {
			log.Error(err)
			connect.Close()
			continue
		}

		// drop database deepflow
		log.Info("drop database deepflow")
		sql := "DROP DATABASE IF EXISTS deepflow"
		_, err = connect.Exec(sql)
		if err != nil {
			log.Error(err)
			connect.Close()
			continue
		}

		sort.Strings(databases)
		databaseIndex := sort.SearchStrings(databases, c.cfg.ClickHouseCfg.Database)
		if len(databases) == 0 || databaseIndex == len(databases) || databases[databaseIndex] != c.cfg.ClickHouseCfg.Database {
			log.Infof("create database %s", c.cfg.ClickHouseCfg.Database)
			sql := fmt.Sprintf("CREATE DATABASE %s", c.cfg.ClickHouseCfg.Database)
			_, err = connect.Exec(sql)
			if err != nil {
				log.Error(err)
				connect.Close()
				continue
			}
		}

		// 获取数据库中当前的字典
		dictionaries := []string{}
		if err := connect.Select(&dictionaries, fmt.Sprintf("SHOW DICTIONARIES IN %s", c.cfg.ClickHouseCfg.Database)); err != nil {
			log.Error(err)
			connect.Close()
			continue
		}
		wantedDicts := mapset.NewSet(
			CH_DICTIONARY_IP_RESOURCE,
			CH_DICTIONARY_IP_RELATION,
			CH_DICTIONARY_K8S_LABEL,
			CH_DICTIONARY_K8S_LABELS,
			CH_DICTIONARY_REGION,
			CH_DICTIONARY_AZ,
			CH_DICTIONARY_VPC,
			CH_DICTIONARY_VL2,
			CH_DICTIONARY_POD_CLUSTER,
			CH_DICTIONARY_POD_NAMESPACE,
			CH_DICTIONARY_POD_NODE,
			CH_DICTIONARY_POD_GROUP,
			CH_DICTIONARY_POD,
			CH_DICTIONARY_DEVICE,
			CH_DICTIONARY_VTAP_PORT,
			CH_DICTIONARY_TAP_TYPE,
			CH_DICTIONARY_VTAP,
			CH_DICTIONARY_VTAP_PORT,
			CH_DICTIONARY_POD_NODE_PORT,
			CH_DICTIONARY_POD_GROUP_PORT,
			CH_DICTIONARY_POD_PORT,
			CH_DICTIONARY_DEVICE_PORT,
			CH_DICTIONARY_IP_PORT,
			CH_DICTIONARY_SERVER_PORT,
			CH_DICTIONARY_LB_LISTENER,
			CH_DICTIONARY_POD_INGRESS,
			CH_STRING_DICTIONARY_ENUM,
			CH_INT_DICTIONARY_ENUM)
		chDicts := mapset.NewSet()
		for _, dictionary := range dictionaries {
			chDicts.Add(dictionary)
		}

		// 删除不存在的字典
		delDicts := chDicts.Difference(wantedDicts)
		for _, dict := range delDicts.ToSlice() {
			dropSQL := fmt.Sprintf("DROP DICTIONARY %s.%s", c.cfg.ClickHouseCfg.Database, dict)
			_, err = connect.Exec(dropSQL)
			if err != nil {
				log.Error(err)
				connect.Close()
				continue
			}
		}

		// 创建期望的字典
		addDicts := wantedDicts.Difference(chDicts)
		for _, dict := range addDicts.ToSlice() {
			dictName := dict.(string)
			chTable := "ch_" + strings.TrimSuffix(dictName, "_map")
			createSQL := CREATE_SQL_MAP[dictName]
			mysqlPortStr := strconv.Itoa(int(c.cfg.MySqlCfg.Port))
			createSQL = fmt.Sprintf(createSQL, c.cfg.ClickHouseCfg.Database, dictName, mysqlPortStr, c.cfg.MySqlCfg.UserName, c.cfg.MySqlCfg.UserPassword, replicaSQL, c.cfg.MySqlCfg.Database, chTable, chTable)
			log.Infof("create dictionary %s", dictName)
			log.Info(createSQL)
			_, err = connect.Exec(createSQL)
			if err != nil {
				log.Error(err)
				connect.Close()
				continue
			}
		}

		// 检查并更新已存在字典
		checkDicts := chDicts.Intersect(wantedDicts)
		for _, dict := range checkDicts.ToSlice() {
			dictName := dict.(string)
			chTable := "ch_" + strings.TrimSuffix(dictName, "_map")
			showSQL := fmt.Sprintf("SHOW CREATE DICTIONARY %s.%s", c.cfg.ClickHouseCfg.Database, dictName)
			dictSQL := make([]string, 0)
			if err := connect.Select(&dictSQL, showSQL); err != nil {
				log.Error(err)
				connect.Close()
				continue
			}
			createSQL := CREATE_SQL_MAP[dictName]
			mysqlPortStr := strconv.Itoa(int(c.cfg.MySqlCfg.Port))
			createSQL = fmt.Sprintf(createSQL, c.cfg.ClickHouseCfg.Database, dictName, mysqlPortStr, c.cfg.MySqlCfg.UserName, c.cfg.MySqlCfg.UserPassword, replicaSQL, c.cfg.MySqlCfg.Database, chTable, chTable)
			if createSQL == dictSQL[0] {
				continue
			}
			log.Infof("update dictionary %s", dictName)
			log.Infof("exist dictionary %s", dictSQL[0])
			log.Infof("wanted dictionary %s", createSQL)
			dropSQL := fmt.Sprintf("DROP DICTIONARY %s.%s", c.cfg.ClickHouseCfg.Database, dictName)
			_, err = connect.Exec(dropSQL)
			if err != nil {
				log.Error(err)
				connect.Close()
				continue
			}
			_, err = connect.Exec(createSQL)
			if err != nil {
				log.Error(err)
				connect.Close()
				continue
			}
		}
		connect.Close()
	}
	return
}
