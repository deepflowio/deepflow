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
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	mapset "github.com/deckarep/golang-set"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/clickhouse"
)

func (c *TagRecorder) UpdateChDictionary() {
	log.Info("tagrecorder update ch dictionary")
	kubeconfig := c.cfg.Kubeconfig
	var config *rest.Config
	var err error
	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Error(err)
			return
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			log.Error(err)
			return
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return
	}
	ctx := context.Background()
	namespace := os.Getenv(common.NAME_SPACE_KEY)
	endpoints, err := clientset.CoreV1().Endpoints(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Error(err)
		return
	}
	if len(endpoints.Items) == 0 {
		log.Warningf("no endpoints in %s", namespace)
	}
	endpointName := c.cfg.ClickHouseCfg.Host
	for _, endpoint := range endpoints.Items {
		if endpoint.Name != endpointName {
			continue
		}
		subsets := endpoint.Subsets
		for _, subset := range subsets {
			for _, address := range subset.Addresses {
				clickHouseCfg := c.cfg.ClickHouseCfg
				clickHouseCfg.Host = address.IP
				for _, port := range subset.Ports {
					if port.Name == "tcp-port" {
						clickHouseCfg.Port = uint32(port.Port)
						// 在本区域所有数据节点更新字典
						// Update the dictionary at all data nodes in the region
						replicaSQL := fmt.Sprintf("REPLICA (HOST '%s' PRIORITY %s)", c.cfg.MySqlCfg.Host, "1")
						connect, err := clickhouse.Connect(clickHouseCfg)
						if err != nil {
							continue
						}
						log.Infof("refresh clickhouse dictionary in (%s: %d)", address.IP, clickHouseCfg.Port)
						var databases []string

						// 检查并创建数据库
						// Check and create the database
						if err := connect.Select(&databases, "SHOW DATABASES"); err != nil {
							log.Error(err)
							connect.Close()
							continue
						}
						// 删除deepflow数据库
						// Drop database deepflow
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
						// Get the current dictionary in the database
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
							CH_DICTIONARY_NODE_TYPE,
							CH_STRING_DICTIONARY_ENUM,
							CH_INT_DICTIONARY_ENUM,
						)
						chDicts := mapset.NewSet()
						for _, dictionary := range dictionaries {
							chDicts.Add(dictionary)
						}

						// 删除不存在的字典
						// Delete a dictionary that does not exist
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
						// Creating the desired dictionary
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
						// Check and update existing dictionaries
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
				}
			}
		}
	}
	return
}
