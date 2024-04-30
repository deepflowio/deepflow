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

package service

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

var DEFAULT_DATA_SOURCE_DISPLAY_NAMES = []string{
	"网络-指标（秒级）", "网络-指标（分钟级）", // flow_metrics.network*
	"网络-流日志",                  // flow_log.l4_flow_log
	"应用-指标（秒级）", "应用-指标（分钟级）", // flow_metrics.application*
	"应用-调用日志",       // flow_log.l7_flow_log
	"网络-TCP 时序数据",   // flow_log.l4_packet
	"网络-PCAP 数据",    // flow_log.l7_packet
	"系统监控数据",        // deepflow_system.*
	"外部指标数据",        // ext_metrics.*
	"Prometheus 数据", // prometheus.*
	"事件-资源变更事件",     // event.event
	"事件-IO 事件",      // event.perf_event
	"事件-告警事件",       // event.alarm_event
	"应用-性能剖析",       // profile.in_process
	"网络-网络策略",       // flow_metrics.traffic_policy
}

func GetDataSources(orgID int, filter map[string]interface{}, specCfg *config.Specification) (resp []model.DataSource, err error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB
	var response []model.DataSource
	var dataSources []mysql.DataSource
	var baseDataSources []mysql.DataSource

	if _, ok := filter["lcuuid"]; ok {
		db = db.Where("lcuuid = ?", filter["lcuuid"])
	}
	if t, ok := filter["type"]; ok {
		var collection string
		switch t {
		case "application":
			collection = "flow_metrics.application*"
		case "network":
			collection = "flow_metrics.network*"
		case "deepflow_system":
			collection = "deepflow_system.*"
		case "ext_metrics":
			collection = "ext_metrics.*"
		case "prometheus":
			collection = "prometheus.*"
		case "traffic_policy":
			collection = "flow_metrics.traffic_policy"
		default:
			return nil, fmt.Errorf("not support type(%s)", t)
		}

		db = db.Where("data_table_collection = ?", collection)
	}
	if name, ok := filter["name"]; ok {
		interval := convertNameToInterval(name.(string))
		if interval != 0 {
			db = db.Where("`interval` = ?", interval)
		}
	}
	if err := db.Find(&dataSources).Error; err != nil {
		return nil, err
	}

	if err := db.Find(&baseDataSources).Error; err != nil {
		return nil, err
	}
	idToDisplayName := make(map[int]string)
	for _, baseDataSource := range baseDataSources {
		idToDisplayName[baseDataSource.ID] = baseDataSource.DisplayName
	}

	for _, dataSource := range dataSources {
		name, err := getName(dataSource.Interval, dataSource.DataTableCollection)
		if err != nil {
			log.Error(err)
			return nil, err
		}

		dataSourceResp := model.DataSource{
			ID:                        dataSource.ID,
			Name:                      name,
			DisplayName:               dataSource.DisplayName,
			Lcuuid:                    dataSource.Lcuuid,
			DataTableCollection:       dataSource.DataTableCollection,
			State:                     dataSource.State,
			BaseDataSourceID:          dataSource.BaseDataSourceID,
			Interval:                  dataSource.Interval,
			RetentionTime:             dataSource.RetentionTime,
			SummableMetricsOperator:   dataSource.SummableMetricsOperator,
			UnSummableMetricsOperator: dataSource.UnSummableMetricsOperator,
			UpdatedAt:                 dataSource.UpdatedAt.Format(common.GO_BIRTHDAY),
		}
		if baseDisplayName, ok := idToDisplayName[dataSource.BaseDataSourceID]; ok {
			dataSourceResp.BaseDataSourceDisplayName = baseDisplayName
		}
		sort.Strings(DEFAULT_DATA_SOURCE_DISPLAY_NAMES)
		index := sort.SearchStrings(DEFAULT_DATA_SOURCE_DISPLAY_NAMES, dataSource.DisplayName)
		if index < len(DEFAULT_DATA_SOURCE_DISPLAY_NAMES) && DEFAULT_DATA_SOURCE_DISPLAY_NAMES[index] == dataSource.DisplayName {
			dataSourceResp.IsDefault = true
		} else {
			dataSourceResp.IsDefault = false
		}
		if specCfg != nil {
			if dataSource.DataTableCollection == "deepflow_system.*" {
				dataSourceResp.Interval = common.DATA_SOURCE_DEEPFLOW_SYSTEM_INTERVAL
			}
			if dataSource.DataTableCollection == "ext_metrics.*" {
				dataSourceResp.Interval = specCfg.DataSourceExtMetricsInterval
			}
			if dataSource.DataTableCollection == "prometheus.*" {
				dataSourceResp.Interval = specCfg.DataSourcePrometheusInterval
			}
		}

		response = append(response, dataSourceResp)
	}
	return response, nil
}

func CreateDataSource(orgID int, dataSourceCreate *model.DataSourceCreate, cfg *config.ControllerConfig) (model.DataSource, error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return model.DataSource{}, err
	}
	db := dbInfo.DB
	var dataSource mysql.DataSource
	var baseDataSource mysql.DataSource
	var dataSourceCount int64

	if ret := db.Where(
		map[string]interface{}{
			"data_table_collection": dataSourceCreate.DataTableCollection,
			"interval":              dataSourceCreate.Interval,
		},
	).First(&dataSource); ret.Error == nil {
		return model.DataSource{}, NewError(
			httpcommon.RESOURCE_ALREADY_EXIST,
			fmt.Sprintf("data_source with same effect(data_table_collection: %v, interval: %v) already exists",
				dataSourceCreate.DataTableCollection, dataSourceCreate.Interval),
		)
	}

	if dataSourceCreate.RetentionTime > cfg.Spec.DataSourceRetentionTimeMax {
		return model.DataSource{}, NewError(
			httpcommon.PARAMETER_ILLEGAL,
			fmt.Sprintf("data_source retention_time should le %d", cfg.Spec.DataSourceRetentionTimeMax),
		)
	}

	if err := db.Model(&model.DataSource{}).Count(&dataSourceCount).Error; err != nil {
		return model.DataSource{}, err
	}
	if int(dataSourceCount) >= cfg.Spec.DataSourceMax {
		return model.DataSource{}, NewError(
			httpcommon.RESOURCE_NUM_EXCEEDED,
			fmt.Sprintf("data_source count exceeds (limit %d)", cfg.Spec.DataSourceMax),
		)
	}

	if ret := db.Where("id = ?", dataSourceCreate.BaseDataSourceID).First(&baseDataSource); ret.Error != nil {
		return model.DataSource{}, NewError(
			httpcommon.PARAMETER_ILLEGAL,
			fmt.Sprintf("base data_source (%d) not exist", dataSourceCreate.BaseDataSourceID),
		)
	}

	if baseDataSource.DataTableCollection != dataSourceCreate.DataTableCollection || baseDataSource.Interval == common.INTERVAL_1DAY {
		return model.DataSource{}, NewError(
			httpcommon.PARAMETER_ILLEGAL,
			"base data_source tsdb_type should the same as tsdb and interval should ne 1 day",
		)
	}

	if baseDataSource.Interval >= dataSourceCreate.Interval {
		return model.DataSource{}, NewError(
			httpcommon.PARAMETER_ILLEGAL, "interval should gt base data_source interval",
		)
	}

	if baseDataSource.SummableMetricsOperator == "Sum" && dataSourceCreate.SummableMetricsOperator != "Sum" {
		return model.DataSource{}, NewError(
			httpcommon.PARAMETER_ILLEGAL,
			"summable_metrics_operator only support Sum, if base data_source summable_metrics_operator is Sum",
		)
	}

	if (baseDataSource.SummableMetricsOperator == "Max" || baseDataSource.SummableMetricsOperator == "Min") &&
		!(dataSourceCreate.SummableMetricsOperator == "Max" || dataSourceCreate.SummableMetricsOperator == "Min") {
		return model.DataSource{}, NewError(
			httpcommon.PARAMETER_ILLEGAL,
			"summable_metrics_operator only support Max/Min, if base data_source summable_metrics_operator is Max/Min",
		)
	}

	dataSource = mysql.DataSource{}
	lcuuid := uuid.New().String()
	dataSource.Lcuuid = lcuuid
	dataSource.DisplayName = dataSourceCreate.DisplayName
	dataSource.DataTableCollection = dataSourceCreate.DataTableCollection
	dataSource.BaseDataSourceID = dataSourceCreate.BaseDataSourceID
	dataSource.Interval = dataSourceCreate.Interval
	dataSource.RetentionTime = dataSourceCreate.RetentionTime
	dataSource.SummableMetricsOperator = dataSourceCreate.SummableMetricsOperator
	dataSource.UnSummableMetricsOperator = dataSourceCreate.UnSummableMetricsOperator
	if err := db.Create(&dataSource).Error; err != nil {
		return model.DataSource{}, err
	}

	// 调用ingester API配置clickhouse
	var analyzers []mysql.Analyzer
	if err := db.Find(&analyzers).Error; err != nil {
		return model.DataSource{}, err
	}

	var errStrs []string
	for _, analyzer := range analyzers {
		if ingesterErr := CallIngesterAPIAddRP(orgID, analyzer.IP, dataSource, baseDataSource, cfg.IngesterApi.Port); ingesterErr != nil {
			errStr := fmt.Sprintf(
				"failed to config analyzer (name:%s, ip:%s) add data_source(%s), error: %s",
				analyzer.Name, analyzer.IP, dataSource.DisplayName, ingesterErr.Error(),
			)
			errStrs = append(errStrs, errStr)
			continue
		}
		log.Infof(
			"config analyzer (%s) add data_source (%s) complete",
			analyzer.IP, dataSource.DisplayName,
		)
	}
	if len(errStrs) > 0 {
		errMsg := strings.Join(errStrs, ".") + "."
		err = NewError(httpcommon.STATUES_PARTIAL_CONTENT, errMsg)
		log.Error(errMsg)
	}

	if err != nil {
		if err := db.Model(&dataSource).Updates(
			map[string]interface{}{"state": common.DATA_SOURCE_STATE_EXCEPTION},
		).Error; err != nil {
			return model.DataSource{}, err
		}
	}

	response, _ := GetDataSources(orgID, map[string]interface{}{"lcuuid": lcuuid}, nil)
	return response[0], err
}

func UpdateDataSource(orgID int, lcuuid string, dataSourceUpdate model.DataSourceUpdate, cfg *config.ControllerConfig) (model.DataSource, error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return model.DataSource{}, err
	}
	db := dbInfo.DB
	var dataSource mysql.DataSource
	if ret := db.Where("lcuuid = ?", lcuuid).First(&dataSource); ret.Error != nil {
		return model.DataSource{}, NewError(
			httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("data_source (%s) not found", lcuuid),
		)
	}

	if dataSourceUpdate.RetentionTime > cfg.Spec.DataSourceRetentionTimeMax {
		return model.DataSource{}, NewError(
			httpcommon.INVALID_POST_DATA,
			fmt.Sprintf("data_source retention_time should le %d", cfg.Spec.DataSourceRetentionTimeMax),
		)
	}
	oldRetentionTime := dataSource.RetentionTime
	isUpdateName := false
	if !utils.Find(DEFAULT_DATA_SOURCE_DISPLAY_NAMES, dataSource.DisplayName) {
		dataSource.DisplayName = dataSourceUpdate.DisplayName
		isUpdateName = true
	}

	// only update display name
	if dataSource.RetentionTime == dataSourceUpdate.RetentionTime && isUpdateName {
		err := mysql.Db.Save(&dataSource).Error
		if err != nil {
			return model.DataSource{}, err
		}
		response, _ := GetDataSources(orgID, map[string]interface{}{"lcuuid": lcuuid}, nil)
		return response[0], nil
	}
	dataSource.RetentionTime = dataSourceUpdate.RetentionTime

	// 调用roze API配置clickhouse
	var analyzers []mysql.Analyzer
	if err := db.Find(&analyzers).Error; err != nil {
		return model.DataSource{}, err
	}

	var errs []error
	for _, analyzer := range analyzers {
		err = CallIngesterAPIModRP(orgID, analyzer.IP, dataSource, cfg.IngesterApi.Port)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"failed to config analyzer (name: %s, ip:%s) update data_source (%s) error: %w",
				analyzer.Name, analyzer.IP, dataSource.DisplayName, err,
			))
			continue
		}
		log.Infof("config analyzer (%s) mod data_source (%s) complete, retention time change: %ds -> %ds",
			analyzer.IP, dataSource.DisplayName, oldRetentionTime, dataSource.RetentionTime)
	}

	if len(errs) == 0 {
		dataSource.State = common.DATA_SOURCE_STATE_NORMAL
		if err := db.Save(&dataSource).Error; err != nil {
			return model.DataSource{}, err
		}
		log.Infof("update data_source (%s), retention time change: %ds -> %ds",
			dataSource.DisplayName, oldRetentionTime, dataSource.RetentionTime)
	}
	var errStrs []string
	for _, e := range errs {
		errStrs = append(errStrs, e.Error())
	}
	errMsg := strings.Join(errStrs, ".") + "."

	for _, e := range errs {
		if errors.Is(e, httpcommon.ErrorFail) {
			if err := db.Model(&dataSource).Updates(
				map[string]interface{}{"state": common.DATA_SOURCE_STATE_EXCEPTION},
			).Error; err != nil {
				return model.DataSource{}, err
			}
			err = NewError(httpcommon.STATUES_PARTIAL_CONTENT, errMsg)
			break
		}
	}

	for _, e := range errs {
		if errors.Is(e, httpcommon.ErrorPending) {
			warnMsg := fmt.Sprintf("pending %s", e.Error())
			log.Warning(NewError(httpcommon.CONFIG_PENDING, warnMsg))
			err = NewError(httpcommon.CONFIG_PENDING, warnMsg)
			break
		}
	}

	response, _ := GetDataSources(orgID, map[string]interface{}{"lcuuid": lcuuid}, nil)
	return response[0], err
}

func DeleteDataSource(orgID int, lcuuid string, cfg *config.ControllerConfig) (map[string]string, error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB
	var dataSource mysql.DataSource
	var baseDataSource mysql.DataSource

	if ret := db.Where("lcuuid = ?", lcuuid).First(&dataSource); ret.Error != nil {
		return map[string]string{}, NewError(
			httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("data_source (%s) not found", lcuuid),
		)
	}

	// 默认数据源禁止删除
	sort.Strings(DEFAULT_DATA_SOURCE_DISPLAY_NAMES)
	index := sort.SearchStrings(DEFAULT_DATA_SOURCE_DISPLAY_NAMES, dataSource.DisplayName)
	if index < len(DEFAULT_DATA_SOURCE_DISPLAY_NAMES) && DEFAULT_DATA_SOURCE_DISPLAY_NAMES[index] == dataSource.DisplayName {
		return map[string]string{}, NewError(
			httpcommon.INVALID_POST_DATA, "Not support delete default data_source",
		)
	}

	// 被其他数据源引用的数据源禁止删除
	if ret := db.Where("base_data_source_id = ?", dataSource.ID).First(&baseDataSource); ret.Error == nil {
		return map[string]string{}, NewError(
			httpcommon.INVALID_POST_DATA,
			fmt.Sprintf("data_source (%s) is used by other data_source", dataSource.DisplayName),
		)
	}

	log.Infof("delete data_source (%s)", dataSource.DisplayName)

	// 调用ingester API配置clickhouse
	var analyzers []mysql.Analyzer
	if err := db.Find(&analyzers).Error; err != nil {
		return nil, err
	}

	var errStrs []string
	for _, analyzer := range analyzers {
		if ingesterErr := CallIngesterAPIDelRP(orgID, analyzer.IP, dataSource, cfg.IngesterApi.Port); ingesterErr != nil {
			errStr := fmt.Sprintf(
				"failed to config analyzer (name: %s, ip:%s) delete data_source (%s) error(%s)",
				analyzer.Name, analyzer.IP, dataSource.DisplayName, ingesterErr.Error(),
			)
			errStrs = append(errStrs, errStr)
			continue
		}
		log.Infof(
			"config analyzer (%s) del data_source (%s) complete",
			analyzer.IP, dataSource.DisplayName,
		)
	}

	if len(errStrs) > 0 {
		if err := db.Model(&dataSource).Updates(
			map[string]interface{}{"state": common.DATA_SOURCE_STATE_EXCEPTION},
		).Error; err != nil {
			return nil, err
		}
	}
	if len(errStrs) > 0 {
		errMsg := strings.Join(errStrs, ".") + "."
		err = NewError(httpcommon.SERVER_ERROR, errMsg)
		log.Error(errMsg)
	}
	if e := db.Delete(&dataSource).Error; e != nil {
		return nil, e
	}

	return map[string]string{"LCUUID": lcuuid}, err
}

func CallIngesterAPIAddRP(orgID int, ip string, dataSource, baseDataSource mysql.DataSource, ingesterApiPort int) error {
	var name, baseName string
	var err error
	if name, err = getName(dataSource.Interval, dataSource.DataTableCollection); err != nil {
		return err
	}
	if baseName, err = getName(baseDataSource.Interval, baseDataSource.DataTableCollection); err != nil {
		return err
	}
	body := map[string]interface{}{
		common.INGESTER_BODY_ORG_ID: orgID,
		"name":                      name,
		"db":                        getTableName(dataSource.DataTableCollection),
		"base-rp":                   baseName,
		"summable-metrics-op":       strings.ToLower(dataSource.SummableMetricsOperator),
		"unsummable-metrics-op":     strings.ToLower(dataSource.UnSummableMetricsOperator),
		"interval":                  dataSource.Interval / common.INTERVAL_1MINUTE,
		"retention-time":            dataSource.RetentionTime,
	}
	url := fmt.Sprintf("http://%s:%d/v1/rpadd/", common.GetCURLIP(ip), ingesterApiPort)
	log.Infof("call add data_source, url: %s, body: %v", url, body)
	_, err = common.CURLPerform("POST", url, body, common.WithORGHeader(strconv.Itoa(orgID)))
	if err != nil && !(errors.Is(err, httpcommon.ErrorPending) || errors.Is(err, httpcommon.ErrorFail)) {
		err = fmt.Errorf("%w, %s", httpcommon.ErrorFail, err.Error())
	}
	return err
}

func CallIngesterAPIModRP(orgID int, ip string, dataSource mysql.DataSource, ingesterApiPort int) error {
	name, err := getName(dataSource.Interval, dataSource.DataTableCollection)
	if err != nil {
		return err
	}
	body := map[string]interface{}{
		common.INGESTER_BODY_ORG_ID: orgID,
		"name":                      name,
		"db":                        getTableName(dataSource.DataTableCollection),
		"retention-time":            dataSource.RetentionTime,
	}
	url := fmt.Sprintf("http://%s:%d/v1/rpmod/", common.GetCURLIP(ip), ingesterApiPort)
	log.Infof("call mod data_source, url: %s, body: %v", url, body)
	_, err = common.CURLPerform("PATCH", url, body, common.WithORGHeader(strconv.Itoa(orgID)))
	if err != nil && !(errors.Is(err, httpcommon.ErrorPending) || errors.Is(err, httpcommon.ErrorFail)) {
		err = fmt.Errorf("%w, %s", httpcommon.ErrorFail, err.Error())
	}
	return err
}

func CallIngesterAPIDelRP(orgID int, ip string, dataSource mysql.DataSource, ingesterApiPort int) error {
	name, err := getName(dataSource.Interval, dataSource.DataTableCollection)
	if err != nil {
		return err
	}
	body := map[string]interface{}{
		common.INGESTER_BODY_ORG_ID: orgID,
		"name":                      name,
		"db":                        getTableName(dataSource.DataTableCollection),
	}
	url := fmt.Sprintf("http://%s:%d/v1/rpdel/", common.GetCURLIP(ip), ingesterApiPort)
	log.Infof("call del data_source, url: %s, body: %v", url, body)
	_, err = common.CURLPerform("DELETE", url, body, common.WithORGHeader(strconv.Itoa(orgID)))
	if err != nil && !(errors.Is(err, httpcommon.ErrorPending) || errors.Is(err, httpcommon.ErrorFail)) {
		err = fmt.Errorf("%w, %s", httpcommon.ErrorFail, err.Error())
	}
	return err
}

func getName(interval int, collection string) (string, error) {
	switch interval {
	case 0:
		// return value: flow_log.l4_flow_log, flow_log.l7_flow_log,
		// flow_log.l4_packet, flow_log.l7_packet,
		// deepflow_system, ext_metrics, prometheus,
		// event.event, event.perf_event, event.alarm_event
		return strings.TrimSuffix(collection, ".*"), nil
	case 1: // one second
		return "1s", nil
	case 60: // one minute, 60*1
		return "1m", nil
	case 3600: // one hour, 60*60
		return "1h", nil
	case 86400: // one day, 60*60*24
		return "1d", nil
	default:
		return "", fmt.Errorf("get name error, interval does not support value: %d", interval)
	}
}

func convertNameToInterval(name string) (interval int) {
	switch name {
	case "1s":
		return 1
	case "1m":
		return 60
	case "1h":
		return 3600
	case "1d":
		return 86400
	default:
		log.Errorf("unsupported name: %s", name)
		return 0
	}
}

func getTableName(collection string) string {
	name := collection
	if collection == common.DATA_SOURCE_APPLICATION || collection == common.DATA_SOURCE_NETWORK || collection == common.DATA_SOURCE_TRAFFIC_POLICY {
		name = strings.TrimPrefix(name, "flow_metrics.")
		name = strings.TrimSuffix(name, "*")
	}
	return strings.TrimSuffix(name, ".*")
}

func ConfigAnalyzerDataSource(ip string) error {
	var dataSources []mysql.DataSource
	var err error

	// TODO(weiqiang): add org to register analyzer
	if err := mysql.Db.Find(&dataSources).Error; err != nil {
		return err
	}
	idToDataSource := make(map[int]mysql.DataSource)
	for _, dataSource := range dataSources {
		idToDataSource[dataSource.ID] = dataSource
	}

	for _, dataSource := range dataSources {
		// default data_source modify retention policy
		// custom data_source add retention policy
		sort.Strings(DEFAULT_DATA_SOURCE_DISPLAY_NAMES)
		index := sort.SearchStrings(DEFAULT_DATA_SOURCE_DISPLAY_NAMES, dataSource.DisplayName)
		if index < len(DEFAULT_DATA_SOURCE_DISPLAY_NAMES) && DEFAULT_DATA_SOURCE_DISPLAY_NAMES[index] == dataSource.DisplayName {
			if CallIngesterAPIModRP(common.DEFAULT_ORG_ID, ip, dataSource, common.INGESTER_API_PORT) != nil {
				errMsg := fmt.Sprintf(
					"config analyzer (%s) mod data_source (%s) failed", ip, dataSource.DisplayName,
				)
				log.Error(errMsg)
				err = NewError(httpcommon.SERVER_ERROR, errMsg)
				continue
			}
		} else {
			baseDataSource, ok := idToDataSource[dataSource.BaseDataSourceID]
			if !ok {
				errMsg := fmt.Sprintf("base data_source (%d) not exist", dataSource.BaseDataSourceID)
				log.Error(errMsg)
				err = NewError(httpcommon.SERVER_ERROR, errMsg)
				continue
			}
			if CallIngesterAPIAddRP(common.DEFAULT_ORG_ID, ip, dataSource, baseDataSource, common.INGESTER_API_PORT) != nil {
				errMsg := fmt.Sprintf(
					"config analyzer (%s) add data_source (%s) failed", ip, dataSource.DisplayName,
				)
				log.Error(errMsg)
				err = NewError(httpcommon.SERVER_ERROR, errMsg)
				continue
			}
		}
		log.Infof(
			"config analyzer (%s) mod data_source (%s) complete", ip, dataSource.DisplayName,
		)
	}

	return err
}
