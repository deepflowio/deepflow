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
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/clickhouse"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metaDBCommon "github.com/deepflowio/deepflow/server/controller/db/metadb/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var (
	dictionaryOnce sync.Once
	dictionary     *Dictionary
)

type Dictionary struct {
	cfg    config.ControllerConfig
	source metaDBCommon.ClickHouseSource
}

func GetDictionary() *Dictionary {
	dictionaryOnce.Do(func() {
		dictionary = &Dictionary{}
	})
	return dictionary
}

func (c *Dictionary) Init(cfg config.ControllerConfig) {
	c.cfg = cfg
	c.source = metaDBCommon.GetClickhouseSource(c.cfg.MetadbCfg)
}

func (c *Dictionary) Start(sCtx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Duration(c.cfg.TagRecorderCfg.Interval) * time.Second)
		defer ticker.Stop()
		count := 0
		times := c.cfg.TagRecorderCfg.DictionaryReloadInterval / c.cfg.TagRecorderCfg.Interval
	LOOP:
		for {
			select {
			case <-ticker.C:
				count++
				if count >= times {
					c.Update(c.reloadDict)
					count = 0
				} else {
					c.Update(c.update)
				}
			case <-sCtx.Done():
				break LOOP
			}
		}
	}()
}

func (c *Dictionary) reloadDict(clickHouseCfg *clickhouse.ClickHouseConfig) {
	// reload the dictionary at all data nodes in the region
	ckDb, err := clickhouse.Connect(*clickHouseCfg)
	if err != nil {
		log.Error(err)
		return
	}
	defer ckDb.Close()
	log.Infof("reload clickhouse dictionary in (%s: %d)", clickHouseCfg.Host, clickHouseCfg.Port)
	reloadSql := "SYSTEM RELOAD DICTIONARIES"
	_, err = ckDb.Exec(reloadSql)
	if err != nil {
		log.Error(err)
		return
	}
}

func (c *Dictionary) Update(updateFunc func(*clickhouse.ClickHouseConfig)) {
	log.Info("tagrecorder update ch dictionary")
	if common.IsStandaloneRunningMode() {
		// in standalone mode, only supports one ClickHouse node
		updateFunc(&c.cfg.ClickHouseCfg)
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
					if port.Name == c.cfg.ClickHouseCfg.EndpointTcpPortName {
						clickHouseCfg.Port = uint32(port.Port)
						updateFunc(&clickHouseCfg)
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

func (c *Dictionary) update(clickHouseCfg *clickhouse.ClickHouseConfig) {
	// 在本区域所有数据节点更新字典
	// Update the dictionary at all data nodes in the region
	sqlDatabaseName := c.source.Database
	ckDatabaseName := c.cfg.ClickHouseCfg.Database
	ckDb, err := clickhouse.Connect(*clickHouseCfg)
	if err != nil {
		log.Error(err)
		return
	}
	defer ckDb.Close()

	log.Infof("refresh clickhouse dictionary in (%s: %d)", clickHouseCfg.Host, clickHouseCfg.Port)

	wantedDicts := mapset.NewSet(
		CH_DICTIONARY_IP_RESOURCE,
		CH_DICTIONARY_IP_RELATION,
		CH_DICTIONARY_POD_K8S_LABEL,
		CH_DICTIONARY_POD_K8S_LABELS,
		CH_DICTIONARY_REGION,
		CH_DICTIONARY_AZ,
		CH_DICTIONARY_VPC,
		CH_DICTIONARY_NETWORK,
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
		CH_DICTIONARY_USER,

		CH_DICTIONARY_POD_K8S_ANNOTATION,
		CH_DICTIONARY_POD_K8S_ANNOTATIONS,
		CH_DICTIONARY_POD_SERVICE_K8S_ANNOTATION,
		CH_DICTIONARY_POD_SERVICE_K8S_ANNOTATIONS,
		CH_DICTIONARY_POD_K8S_ENV,
		CH_DICTIONARY_POD_K8S_ENVS,
		CH_DICTIONARY_POD_SERVICE,
		CH_DICTIONARY_CHOST,
		CH_DICTIONARY_BIZ_SERVICE,
		CH_TARGET_LABEL,
		CH_APP_LABEL,
		CH_PROMETHEUS_LABEL_NAME,
		CH_PROMETHEUS_METRIC_NAME,
		CH_PROMETHEUS_METRIC_APP_LABEL_LAYOUT,
		CH_PROMETHEUS_TARGET_LABEL_LAYOUT,

		CH_DICTIONARY_POLICY,
		CH_DICTIONARY_NPB_TUNNEL,
		CH_DICTIONARY_ALARM_POLICY,
		CH_DICTIONARY_CUSTOM_BIZ_SERVICE,
		CH_DICTIONARY_CUSTOM_BIZ_SERVICE_FILTER,
	)
	// 根据不同的组织进行更新
	orgIDs, err := metadb.GetORGIDs()
	if err != nil {
		log.Errorf("get org info fail : %s", err)
	}
	for _, orgID := range orgIDs {
		if orgID != metaDBCommon.DEFAULT_ORG_ID {
			sqlDatabaseName = "`" + fmt.Sprintf(metaDBCommon.DATABASE_PREFIX_ALIGNMENT, orgID) + "_" + c.source.Database + "`"
			ckDatabaseName = "`" + fmt.Sprintf(metaDBCommon.DATABASE_PREFIX_ALIGNMENT, orgID) + "_" + c.cfg.ClickHouseCfg.Database + "`"
		}
		var databases []string
		// 检查并创建数据库
		// Check and create the database
		if err = ckDb.Select(&databases, "SHOW DATABASES"); err != nil {
			log.Error(err, logger.NewORGPrefix(orgID))
			return
		}
		// 删除deepflow数据库
		// Drop database deepflow
		if slices.Contains(databases, "deepflow") {
			dropSql := "DROP DATABASE IF EXISTS deepflow"
			_, err = ckDb.Exec(dropSql)
			if err != nil {
				log.Error(err, logger.NewORGPrefix(orgID))
				return
			}
		}

		sort.Strings(databases)
		databaseIndex := sort.SearchStrings(databases, strings.Trim(ckDatabaseName, "`"))
		if len(databases) == 0 || databaseIndex == len(databases) || databases[databaseIndex] != strings.Trim(ckDatabaseName, "`") {
			log.Infof("create database %s", ckDatabaseName, logger.NewORGPrefix(orgID))
			sql := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", ckDatabaseName)
			_, err = ckDb.Exec(sql)
			if err != nil {
				log.Error(err, logger.NewORGPrefix(orgID))
				return
			}
		}

		// 获取数据库中当前的字典
		// Get the current dictionary in the database
		dictionaries := []string{}
		if err := ckDb.Select(&dictionaries, fmt.Sprintf("SHOW DICTIONARIES IN %s", ckDatabaseName)); err != nil {
			log.Error(err, logger.NewORGPrefix(orgID))
			return
		}

		chDicts := mapset.NewSet()
		for _, dictionary := range dictionaries {
			chDicts.Add(dictionary)
		}

		// 删除不存在的字典
		// Delete a dictionary that does not exist
		delDicts := chDicts.Difference(wantedDicts)
		var delDictError error
		for _, dict := range delDicts.ToSlice() {
			dropSQL := fmt.Sprintf("DROP DICTIONARY %s.%s", ckDatabaseName, dict)
			_, err = ckDb.Exec(dropSQL)
			if err != nil {
				delDictError = err
				log.Error(err, logger.NewORGPrefix(orgID))
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
			createSQL := c.fillCreateSQL(dictName, ckDatabaseName, sqlDatabaseName)
			log.Infof("create dictionary %s", dictName, logger.NewORGPrefix(orgID))
			log.Info(createSQL, logger.NewORGPrefix(orgID))
			_, err = ckDb.Exec(createSQL)
			if err != nil {
				addDictError = err
				log.Error(err, logger.NewORGPrefix(orgID))
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
			showSQL := fmt.Sprintf("SHOW CREATE DICTIONARY %s.%s", ckDatabaseName, dictName)
			dictSQL := make([]string, 0)
			if err := ckDb.Select(&dictSQL, showSQL); err != nil {
				updateDictError = err
				log.Error(err, logger.NewORGPrefix(orgID))
				break
			}
			if len(dictSQL) <= 0 {
				break
			}
			createSQL := c.fillCreateSQL(dictName, ckDatabaseName, sqlDatabaseName)
			// In the new version of CK (version after 23.8), when ‘SHOW CREATE DICTIONARY’ does not display plain text password information, the password is fixedly displayed as ‘[HIDDEN]’, and password comparison needs to be repair.
			checkDictSQL := strings.Replace(dictSQL[0], "[HIDDEN]", c.source.UserPassword, 1)
			if createSQL == checkDictSQL {
				continue
			}
			logCheckSQL := strings.Replace(checkDictSQL, c.source.UserPassword, "[HIDDEN]", 1)
			logCreateSQL := strings.Replace(createSQL, c.source.UserPassword, "[HIDDEN]", 1)
			log.Infof("update dictionary %s", dictName, logger.NewORGPrefix(orgID))
			log.Infof("exist dictionary %s", logCheckSQL, logger.NewORGPrefix(orgID))
			log.Infof("wanted dictionary %s", logCreateSQL, logger.NewORGPrefix(orgID))
			dropSQL := fmt.Sprintf("DROP DICTIONARY %s.%s", ckDatabaseName, dictName)
			_, err = ckDb.Exec(dropSQL)
			if err != nil {
				updateDictError = err
				log.Error(err, logger.NewORGPrefix(orgID))
				break
			}
			_, err = ckDb.Exec(createSQL)
			if err != nil {
				updateDictError = err
				log.Error(err, logger.NewORGPrefix(orgID))
				break
			}
		}
		if updateDictError != nil {
			return
		}
		// Get version
		versions := []string{}
		if err := ckDb.Select(&versions, "SELECT version()"); err != nil {
			log.Error(err, logger.NewORGPrefix(orgID))
			return
		}
		if common.CompareVersion(versions[0], common.CLICK_HOUSE_VERSION) >= 0 {
			continue
		}
		// Get the current view in the database
		views := []string{}
		if err := ckDb.Select(&views, fmt.Sprintf("SHOW TABLES FROM %s LIKE '%%view'", ckDatabaseName)); err != nil {
			log.Error(err, logger.NewORGPrefix(orgID))
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
			createSQL = fmt.Sprintf(createSQL, ckDatabaseName, c.cfg.TagRecorderCfg.LiveViewRefreshSecond, ckDatabaseName)
			_, err = ckDb.Exec(createSQL)
			if err != nil {
				addViewError = err
				log.Error(err, logger.NewORGPrefix(orgID))
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
			showSQL := fmt.Sprintf("SHOW CREATE TABLE %s.%s", ckDatabaseName, viewName)
			viewSQL := make([]string, 0)
			if err := ckDb.Select(&viewSQL, showSQL); err != nil {
				updateViewError = err
				log.Error(err, logger.NewORGPrefix(orgID))
				break
			}
			if len(viewSQL) <= 0 {
				break
			}
			createSQL := CREATE_SQL_MAP[viewName]
			createSQL = fmt.Sprintf(createSQL, ckDatabaseName, c.cfg.TagRecorderCfg.LiveViewRefreshSecond, ckDatabaseName)
			if createSQL == viewSQL[0] {
				continue
			}
			log.Infof("update view %s", viewName, logger.NewORGPrefix(orgID))
			log.Infof("exist view %s", viewSQL[0], logger.NewORGPrefix(orgID))
			log.Infof("wanted view %s", createSQL, logger.NewORGPrefix(orgID))
			dropSQL := fmt.Sprintf("DROP TABLE %s.%s", ckDatabaseName, viewName)
			_, err = ckDb.Exec(dropSQL)
			if err != nil {
				updateViewError = err
				log.Error(err, logger.NewORGPrefix(orgID))
				break
			}
			_, err = ckDb.Exec(createSQL)
			if err != nil {
				updateViewError = err
				log.Error(err, logger.NewORGPrefix(orgID))
				break
			}
		}
		if updateViewError != nil {
			return
		}

	}

}

func (c *Dictionary) makeSourceClause(db, table string) string {
	switch c.source.Name {
	case metaDBCommon.SOURCE_MYSQL, metaDBCommon.SOURCE_POSTGRESQL:
		return fmt.Sprintf(
			SQL_SOURCE_MYSQL, c.source.Name, c.source.Host, c.source.Port, c.source.UserName, c.source.UserPassword, c.source.ReplicaSQL, db, table, table,
		)
	case metaDBCommon.SOURCE_DM:
		return fmt.Sprintf(
			SQL_SOURCE_DM, c.source.DSN, db, table, db, table,
		)
	default:
		return ""
	}
}

func (c *Dictionary) fillCreateSQL(dictName string, ckDatabaseName string, sqlDatabaseName string) string {
	chTable := chDictNameToMetaDBTableName(dictName)
	sourceClause := c.makeSourceClause(sqlDatabaseName, chTable)
	createSQL := CREATE_SQL_MAP[dictName]
	return fmt.Sprintf(
		createSQL,
		ckDatabaseName,
		dictName,
		sourceClause,
		c.cfg.TagRecorderCfg.DictionaryRefreshInterval,
	)
}
