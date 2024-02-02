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

package tagrecorder

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"

	mapset "github.com/deckarep/golang-set"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/clickhouse"
)

func (c *TagRecorder) UpdateChDictionary() {
	log.Info("tagrecorder update ch dictionary")
	if common.IsStandaloneRunningMode() {
		// in standalone mode, only supports one ClickHouse node
		c.updateChDictionary(&c.cfg.ClickHouseCfg)
		return
	}

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
	findEndpoint := false
	for _, endpoint := range endpoints.Items {
		if endpoint.Name != endpointName {
			continue
		}
		findEndpoint = true
		subsets := endpoint.Subsets
		for _, subset := range subsets {
			for _, address := range subset.Addresses {
				clickHouseCfg := c.cfg.ClickHouseCfg
				if strings.Contains(address.IP, ":") {
					clickHouseCfg.Host = fmt.Sprintf("[%s]", address.IP)
				} else {
					clickHouseCfg.Host = address.IP
				}
				for _, port := range subset.Ports {
					if port.Name == "tcp-port" {
						clickHouseCfg.Port = uint32(port.Port)
						c.updateChDictionary(&clickHouseCfg)
					}
				}
			}
		}
	}
	if !findEndpoint {
		log.Warningf("%s endpoint not found!", endpointName)
	}
	return
}

func (c *TagRecorder) updateChDictionary(clickHouseCfg *clickhouse.ClickHouseConfig) {
	// 在本区域所有数据节点更新字典
	// Update the dictionary at all data nodes in the region
	replicaSQL := fmt.Sprintf("REPLICA (HOST '%s' PRIORITY %s)", c.cfg.MySqlCfg.Host, "1")

	ckDb, err := clickhouse.Connect(*clickHouseCfg)
	if err != nil {
		log.Error(err)
		return
	}
	defer ckDb.Close()

	log.Infof("refresh clickhouse dictionary in (%s: %d)", clickHouseCfg.Host, clickHouseCfg.Port)

	var databases []string
	// 检查并创建数据库
	// Check and create the database
	if err = ckDb.Select(&databases, "SHOW DATABASES"); err != nil {
		log.Error(err)
		return
	}
	// 删除deepflow数据库
	// Drop database deepflow
	if slices.Contains(databases, "deepflow") {
		dropSql := "DROP DATABASE IF EXISTS deepflow"
		_, err = ckDb.Exec(dropSql)
		if err != nil {
			log.Error(err)
			return
		}
	}

	sort.Strings(databases)
	databaseIndex := sort.SearchStrings(databases, c.cfg.ClickHouseCfg.Database)
	if len(databases) == 0 || databaseIndex == len(databases) || databases[databaseIndex] != c.cfg.ClickHouseCfg.Database {
		log.Infof("create database %s", c.cfg.ClickHouseCfg.Database)
		sql := fmt.Sprintf("CREATE DATABASE %s", c.cfg.ClickHouseCfg.Database)
		_, err = ckDb.Exec(sql)
		if err != nil {
			log.Error(err)
			return
		}
	}

	// 获取数据库中当前的字典
	// Get the current dictionary in the database
	dictionaries := []string{}
	if err := ckDb.Select(&dictionaries, fmt.Sprintf("SHOW DICTIONARIES IN %s", c.cfg.ClickHouseCfg.Database)); err != nil {
		log.Error(err)
		return
	}
	wantedDicts := mapset.NewSet(
		CH_DICTIONARY_IP_RESOURCE,
		CH_DICTIONARY_IP_RELATION,
		CH_DICTIONARY_POD_K8S_LABEL,
		CH_DICTIONARY_POD_K8S_LABELS,
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
		CH_DICTIONARY_CHOST_CLOUD_TAG,
		CH_DICTIONARY_POD_NS_CLOUD_TAG,
		CH_DICTIONARY_CHOST_CLOUD_TAGS,
		CH_DICTIONARY_POD_NS_CLOUD_TAGS,
		CH_DICTIONARY_OS_APP_TAG,
		CH_DICTIONARY_OS_APP_TAGS,
		CH_DICTIONARY_GPROCESS,
		CH_DICTIONARY_POD_SERVICE_K8S_LABEL,
		CH_DICTIONARY_POD_SERVICE_K8S_LABELS,

		CH_DICTIONARY_POD_K8S_ANNOTATION,
		CH_DICTIONARY_POD_K8S_ANNOTATIONS,
		CH_DICTIONARY_POD_SERVICE_K8S_ANNOTATION,
		CH_DICTIONARY_POD_SERVICE_K8S_ANNOTATIONS,
		CH_DICTIONARY_POD_K8S_ENV,
		CH_DICTIONARY_POD_K8S_ENVS,
		CH_DICTIONARY_POD_SERVICE,
		CH_DICTIONARY_CHOST,
		CH_TARGET_LABEL,
		CH_APP_LABEL,
		CH_PROMETHEUS_LABEL_NAME,
		CH_PROMETHEUS_METRIC_NAME,
		CH_PROMETHEUS_METRIC_APP_LABEL_LAYOUT,
		CH_PROMETHEUS_TARGET_LABEL_LAYOUT,

		CH_DICTIONARY_POLICY,
		CH_DICTIONARY_NPB_TUNNEL,
	)
	chDicts := mapset.NewSet()
	for _, dictionary := range dictionaries {
		chDicts.Add(dictionary)
	}

	// 删除不存在的字典
	// Delete a dictionary that does not exist
	delDicts := chDicts.Difference(wantedDicts)
	var delDictError error
	for _, dict := range delDicts.ToSlice() {
		dropSQL := fmt.Sprintf("DROP DICTIONARY %s.%s", c.cfg.ClickHouseCfg.Database, dict)
		_, err = ckDb.Exec(dropSQL)
		if err != nil {
			delDictError = err
			log.Error(err)
			break
		}
	}
	if delDictError != nil {
		return
	}

	// 创建期望的字典
	// Creating the desired dictionary
	addDicts := wantedDicts.Difference(chDicts)
	var addDictError error
	for _, dict := range addDicts.ToSlice() {
		dictName := dict.(string)
		chTable := "ch_" + strings.TrimSuffix(dictName, "_map")
		createSQL := CREATE_SQL_MAP[dictName]
		mysqlPortStr := strconv.Itoa(int(c.cfg.MySqlCfg.Port))
		createSQL = fmt.Sprintf(createSQL, c.cfg.ClickHouseCfg.Database, dictName, mysqlPortStr, c.cfg.MySqlCfg.UserName, c.cfg.MySqlCfg.UserPassword, replicaSQL, c.cfg.MySqlCfg.Database, chTable, chTable, c.cfg.TagRecorderCfg.DictionaryRefreshInterval)
		log.Infof("create dictionary %s", dictName)
		log.Info(createSQL)
		_, err = ckDb.Exec(createSQL)
		if err != nil {
			addDictError = err
			log.Error(err)
			break
		}
	}
	if addDictError != nil {
		return
	}

	// 检查并更新已存在字典
	// Check and update existing dictionaries
	checkDicts := chDicts.Intersect(wantedDicts)
	var updateDictError error
	for _, dict := range checkDicts.ToSlice() {
		dictName := dict.(string)
		chTable := "ch_" + strings.TrimSuffix(dictName, "_map")
		showSQL := fmt.Sprintf("SHOW CREATE DICTIONARY %s.%s", c.cfg.ClickHouseCfg.Database, dictName)
		dictSQL := make([]string, 0)
		if err := ckDb.Select(&dictSQL, showSQL); err != nil {
			updateDictError = err
			log.Error(err)
			break
		}
		createSQL := CREATE_SQL_MAP[dictName]
		mysqlPortStr := strconv.Itoa(int(c.cfg.MySqlCfg.Port))
		createSQL = fmt.Sprintf(createSQL, c.cfg.ClickHouseCfg.Database, dictName, mysqlPortStr, c.cfg.MySqlCfg.UserName, c.cfg.MySqlCfg.UserPassword, replicaSQL, c.cfg.MySqlCfg.Database, chTable, chTable, c.cfg.TagRecorderCfg.DictionaryRefreshInterval)
		// In the new version of CK (version after 23.8), when ‘SHOW CREATE DICTIONARY’ does not display plain text password information, the password is fixedly displayed as ‘[HIDDEN]’, and password comparison needs to be repair.
		checkDictSQL := strings.Replace(dictSQL[0], "[HIDDEN]", c.cfg.MySqlCfg.UserPassword, 1)
		if createSQL == checkDictSQL {
			continue
		}
		log.Infof("update dictionary %s", dictName)
		log.Infof("exist dictionary %s", checkDictSQL)
		log.Infof("wanted dictionary %s", createSQL)
		dropSQL := fmt.Sprintf("DROP DICTIONARY %s.%s", c.cfg.ClickHouseCfg.Database, dictName)
		_, err = ckDb.Exec(dropSQL)
		if err != nil {
			updateDictError = err
			log.Error(err)
			break
		}
		_, err = ckDb.Exec(createSQL)
		if err != nil {
			updateDictError = err
			log.Error(err)
			break
		}
	}
	if updateDictError != nil {
		return
	}

	// Get the current view in the database
	views := []string{}
	log.Infof("SHOW TABLES FROM %s LIKE '%%view'", c.cfg.ClickHouseCfg.Database)
	if err := ckDb.Select(&views, fmt.Sprintf("SHOW TABLES FROM %s LIKE '%%view'", c.cfg.ClickHouseCfg.Database)); err != nil {
		log.Error(err)
		return
	}

	// Create the desired view
	wantedViews := mapset.NewSet(CH_APP_LABEL_LIVE_VIEW, CH_TARGET_LABEL_LIVE_VIEW)
	chViews := mapset.NewSet()
	for _, view := range views {
		chViews.Add(view)
	}
	addViews := wantedViews.Difference(chViews)
	var addViewError error
	for _, view := range addViews.ToSlice() {
		viewName := view.(string)
		createSQL := CREATE_SQL_MAP[viewName]
		createSQL = fmt.Sprintf(createSQL, c.cfg.TagRecorderCfg.LiveViewRefreshSecond)
		_, err = ckDb.Exec(createSQL)
		if err != nil {
			addViewError = err
			log.Error(err)
			break
		}
	}
	if addViewError != nil {
		return
	}

	// Check and update existing views
	checkViews := chViews.Intersect(wantedViews)
	var updateViewError error
	for _, view := range checkViews.ToSlice() {
		viewName := view.(string)
		log.Info(viewName)
		showSQL := fmt.Sprintf("SHOW CREATE TABLE %s.%s", c.cfg.ClickHouseCfg.Database, viewName)
		viewSQL := make([]string, 0)
		if err := ckDb.Select(&viewSQL, showSQL); err != nil {
			updateViewError = err
			log.Error(err)
			break
		}
		createSQL := CREATE_SQL_MAP[viewName]
		createSQL = fmt.Sprintf(createSQL, c.cfg.TagRecorderCfg.LiveViewRefreshSecond)
		if createSQL == viewSQL[0] {
			continue
		}
		log.Infof("update view %s", viewName)
		log.Infof("exist view %s", viewSQL[0])
		log.Infof("wanted view %s", createSQL)
		dropSQL := fmt.Sprintf("DROP TABLE %s.%s", c.cfg.ClickHouseCfg.Database, viewName)
		_, err = ckDb.Exec(dropSQL)
		if err != nil {
			updateViewError = err
			log.Error(err)
			break
		}
		_, err = ckDb.Exec(createSQL)
		if err != nil {
			updateViewError = err
			log.Error(err)
			break
		}
	}
	if updateViewError != nil {
		return
	}

}
