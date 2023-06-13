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

package service

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/model"
)

var (
	// DATA_SOURCE_DEFAULT_DATA_TABLE does not support deletion.
	DATA_SOURCE_DEFAULT_DATA_TABLE = []string{"1s", "1m", "l4_flow_log", "l7_flow_log",
		"l4_packet", "l7_packet", "deepflow_system"}

	// Send data table to ingester module for compatibility.
	DATA_TABLE_PREFIX        = "flow_log"
	DATA_TABLE_TO_ADD_PREFIX = []string{"l4_flow_log", "l7_flow_log", "l4_packet", "l7_packet"}
)

func GetDataSources(filter map[string]interface{}) (resp []model.DataSource, err error) {
	var response []model.DataSource
	var dataSources []mysql.DataSource
	var baseDataSources []mysql.DataSource

	Db := mysql.Db
	if _, ok := filter["lcuuid"]; ok {
		Db = Db.Where("lcuuid = ?", filter["lcuuid"])
	}
	if _, ok := filter["type"]; ok {
		Db = Db.Where("tsdb_type = ?", filter["type"])
	}
	if _, ok := filter["data_table"]; ok {
		Db = Db.Where("data_table = ?", filter["data_table"])
	}
	Db.Find(&dataSources)

	mysql.Db.Find(&baseDataSources)
	idToDataTable := make(map[int]string)
	for _, baseDataSource := range baseDataSources {
		idToDataTable[baseDataSource.ID] = baseDataSource.DataTable
	}

	for _, dataSource := range dataSources {
		dataSourceResp := model.DataSource{
			ID:                        dataSource.ID,
			DisplayName:               dataSource.DisplayName,
			DataTableCollection:       dataSource.DataTableCollection,
			DataTable:                 dataSource.DataTable,
			Lcuuid:                    dataSource.Lcuuid,
			TsdbType:                  dataSource.TsdbType,
			State:                     dataSource.State,
			BaseDataSourceID:          dataSource.BaseDataSourceID,
			Interval:                  dataSource.Interval,
			RetentionTime:             dataSource.RetentionTime,
			SummableMetricsOperator:   dataSource.SummableMetricsOperator,
			UnSummableMetricsOperator: dataSource.UnSummableMetricsOperator,
			UpdatedAt:                 dataSource.UpdatedAt.Format(common.GO_BIRTHDAY),
		}
		if baseDataSourceDataTable, ok := idToDataTable[dataSource.BaseDataSourceID]; ok {
			dataSourceResp.BaseDataSourceDataTable = baseDataSourceDataTable
		}
		sort.Strings(DATA_SOURCE_DEFAULT_DATA_TABLE)
		index := sort.SearchStrings(DATA_SOURCE_DEFAULT_DATA_TABLE, dataSource.DataTable)
		if index < len(DATA_SOURCE_DEFAULT_DATA_TABLE) && DATA_SOURCE_DEFAULT_DATA_TABLE[index] == dataSource.DataTable {
			dataSourceResp.IsDefault = true
		} else {
			dataSourceResp.IsDefault = false
		}

		response = append(response, dataSourceResp)
	}
	return response, nil
}

func CreateDataSource(dataSourceCreate *model.DataSourceCreate, cfg *config.ControllerConfig) (model.DataSource, error) {
	var dataSource mysql.DataSource
	var baseDataSource mysql.DataSource
	var dataSourceCount int64
	var err error

	// TODO: 数据表只能包含数字字母和下划线的校验
	if ret := mysql.Db.Where("data_table = ?", dataSourceCreate.DataTable).First(&dataSource); ret.Error == nil {
		return model.DataSource{}, NewError(
			common.RESOURCE_ALREADY_EXIST,
			fmt.Sprintf("data_source (%s) already exist", dataSourceCreate.DataTable),
		)
	}

	if ret := mysql.Db.Where(
		map[string]interface{}{
			"tsdb_type":                   dataSourceCreate.TsdbType,
			"base_data_source_id":         dataSourceCreate.BaseDataSourceID,
			"interval":                    dataSourceCreate.Interval,
			"summable_metrics_operator":   dataSourceCreate.SummableMetricsOperator,
			"unsummable_metrics_operator": dataSourceCreate.UnSummableMetricsOperator,
		},
	).First(&dataSource); ret.Error == nil {
		return model.DataSource{}, NewError(
			common.RESOURCE_ALREADY_EXIST, "data_source with same effect already exists",
		)
	}

	if dataSourceCreate.RetentionTime > cfg.Spec.DataSourceRetentionTimeMax {
		return model.DataSource{}, NewError(
			common.PARAMETER_ILLEGAL,
			fmt.Sprintf("data_source retention_time should le %d", cfg.Spec.DataSourceRetentionTimeMax),
		)
	}

	mysql.Db.Model(&model.DataSource{}).Count(&dataSourceCount)
	if int(dataSourceCount) >= cfg.Spec.DataSourceMax {
		return model.DataSource{}, NewError(
			common.RESOURCE_NUM_EXCEEDED,
			fmt.Sprintf("data_source count exceeds (limit %d)", cfg.Spec.DataSourceMax),
		)
	}

	if ret := mysql.Db.Where("id = ?", dataSourceCreate.BaseDataSourceID).First(&baseDataSource); ret.Error != nil {
		return model.DataSource{}, NewError(
			common.PARAMETER_ILLEGAL,
			fmt.Sprintf("base data_source (%d) not exist", dataSourceCreate.BaseDataSourceID),
		)
	}

	if baseDataSource.TsdbType != dataSourceCreate.TsdbType || baseDataSource.Interval == common.INTERVAL_1DAY {
		return model.DataSource{}, NewError(
			common.PARAMETER_ILLEGAL,
			"base data_source tsdb_type should the same as tsdb and interval should ne 1 day",
		)
	}

	if baseDataSource.Interval >= dataSourceCreate.Interval {
		return model.DataSource{}, NewError(
			common.PARAMETER_ILLEGAL, "interval should gt base data_source interval",
		)
	}

	if baseDataSource.SummableMetricsOperator == "Sum" && dataSourceCreate.SummableMetricsOperator != "Sum" {
		return model.DataSource{}, NewError(
			common.PARAMETER_ILLEGAL,
			"summable_metrics_operator only support Sum, if base data_source summable_metrics_operator is Sum",
		)
	}

	if (baseDataSource.SummableMetricsOperator == "Max" || baseDataSource.SummableMetricsOperator == "Min") &&
		!(dataSourceCreate.SummableMetricsOperator == "Max" || dataSourceCreate.SummableMetricsOperator == "Min") {
		return model.DataSource{}, NewError(
			common.PARAMETER_ILLEGAL,
			"summable_metrics_operator only support Max/Min, if base data_source summable_metrics_operator is Max/Min",
		)
	}

	dataSource = mysql.DataSource{}
	lcuuid := uuid.New().String()
	dataSource.Lcuuid = lcuuid
	dataSource.DisplayName = dataSourceCreate.DisplayName
	dataSource.DataTable = dataSourceCreate.DataTable
	dataSource.DataTableCollection = dataSourceCreate.DataTableCollection
	dataSource.TsdbType = dataSourceCreate.TsdbType
	dataSource.BaseDataSourceID = dataSourceCreate.BaseDataSourceID
	dataSource.Interval = dataSourceCreate.Interval
	dataSource.RetentionTime = dataSourceCreate.RetentionTime
	dataSource.SummableMetricsOperator = dataSourceCreate.SummableMetricsOperator
	dataSource.UnSummableMetricsOperator = dataSourceCreate.UnSummableMetricsOperator
	mysql.Db.Create(&dataSource)

	// 调用roze API配置clickhouse
	var analyzers []mysql.Analyzer
	mysql.Db.Find(&analyzers)

	for _, analyzer := range analyzers {
		if CallRozeAPIAddRP(analyzer.IP, dataSource, baseDataSource, cfg.Roze.Port) != nil {
			errMsg := fmt.Sprintf(
				"config analyzer (%s) add data_source (%s) failed", analyzer.IP, dataSource.DataTable,
			)
			log.Error(errMsg)
			err = NewError(common.SERVER_ERROR, errMsg)
			break
		}
		log.Infof(
			"config analyzer (%s) add data_source (%s) complete",
			analyzer.IP, dataSource.DataTable,
		)
	}

	if err != nil {
		mysql.Db.Model(&dataSource).Updates(
			map[string]interface{}{"state": common.DATA_SOURCE_STATE_EXCEPTION},
		)
	}

	response, _ := GetDataSources(map[string]interface{}{"lcuuid": lcuuid})
	return response[0], err
}

func UpdateDataSource(lcuuid string, dataSourceUpdate model.DataSourceUpdate, cfg *config.ControllerConfig) (model.DataSource, error) {
	var dataSource mysql.DataSource

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&dataSource); ret.Error != nil {
		return model.DataSource{}, NewError(
			common.RESOURCE_NOT_FOUND, fmt.Sprintf("data_source (%s) not found", lcuuid),
		)
	}

	if dataSourceUpdate.RetentionTime > cfg.Spec.DataSourceRetentionTimeMax {
		return model.DataSource{}, NewError(
			common.INVALID_POST_DATA,
			fmt.Sprintf("data_source retention_time should le %d", cfg.Spec.DataSourceRetentionTimeMax),
		)
	}
	oldRetentionTime := dataSource.RetentionTime
	dataSource.RetentionTime = dataSourceUpdate.RetentionTime

	// 调用roze API配置clickhouse
	var analyzers []mysql.Analyzer
	mysql.Db.Find(&analyzers)

	var err error
	var errAnalyzerIP string
	for _, analyzer := range analyzers {
		err = CallRozeAPIModRP(analyzer.IP, dataSource, cfg.Roze.Port)
		if err != nil {
			errAnalyzerIP = analyzer.IP
			break
		}
		log.Infof("config analyzer (%s) mod data_source (%s) complete, retention time change: %ds -> %ds",
			analyzer.IP, dataSource.DataTable, oldRetentionTime, dataSource.RetentionTime)
	}

	if err == nil {
		dataSource.State = common.DATA_SOURCE_STATE_NORMAL
		mysql.Db.Save(&dataSource)
		log.Infof("update data_source (%s), retention time change: %ds -> %ds",
			dataSource.DataTable, oldRetentionTime, dataSource.RetentionTime)
	}
	if errors.Is(err, common.ErrorFail) {
		mysql.Db.Model(&dataSource).Updates(
			map[string]interface{}{"state": common.DATA_SOURCE_STATE_EXCEPTION},
		)
		errMsg := fmt.Sprintf("config analyzer (%s) mod data_source (%s) failed", errAnalyzerIP, dataSource.DataTable)
		log.Error(errMsg)
		err = NewError(common.SERVER_ERROR, errMsg)
	}
	if errors.Is(err, common.ErrorPending) {
		warnMsg := fmt.Sprintf("config analyzer (%s) mod data_source (%s) is pending", errAnalyzerIP, dataSource.DataTable)
		log.Warning(NewError(common.CONFIG_PENDING, warnMsg))
		err = NewError(common.CONFIG_PENDING, warnMsg)
	}

	response, _ := GetDataSources(map[string]interface{}{"lcuuid": lcuuid})
	return response[0], err
}

func DeleteDataSource(lcuuid string, cfg *config.ControllerConfig) (map[string]string, error) {
	var dataSource mysql.DataSource
	var baseDataSource mysql.DataSource
	var err error

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&dataSource); ret.Error != nil {
		return map[string]string{}, NewError(
			common.RESOURCE_NOT_FOUND, fmt.Sprintf("data_source (%s) not found", lcuuid),
		)
	}

	// 默认数据源禁止删除
	sort.Strings(DATA_SOURCE_DEFAULT_DATA_TABLE)
	index := sort.SearchStrings(DATA_SOURCE_DEFAULT_DATA_TABLE, dataSource.DataTable)
	if index < len(DATA_SOURCE_DEFAULT_DATA_TABLE) && DATA_SOURCE_DEFAULT_DATA_TABLE[index] == dataSource.DataTable {
		return map[string]string{}, NewError(
			common.INVALID_POST_DATA, "Not support delete default data_source",
		)
	}

	// 被其他数据源引用的数据源禁止删除
	if ret := mysql.Db.Where("base_data_source_id = ?", dataSource.ID).First(&baseDataSource); ret.Error == nil {
		return map[string]string{}, NewError(
			common.INVALID_POST_DATA,
			fmt.Sprintf("data_source (%s) is used by other data_source", dataSource.DataTable),
		)
	}

	log.Infof("delete data_source (%s)", dataSource.DataTable)

	// 调用roze API配置clickhouse
	var analyzers []mysql.Analyzer
	mysql.Db.Find(&analyzers)

	for _, analyzer := range analyzers {
		if CallRozeAPIDelRP(analyzer.IP, dataSource, cfg.Roze.Port) != nil {
			errMsg := fmt.Sprintf(
				"config analyzer (%s) del data_source (%s) failed", analyzer.IP, dataSource.DataTable,
			)
			log.Error(errMsg)
			err = NewError(common.SERVER_ERROR, errMsg)
			break
		}
		log.Infof(
			"config analyzer (%s) del data_source (%s) complete",
			analyzer.IP, dataSource.DataTable,
		)
	}

	if err != nil {
		mysql.Db.Model(&dataSource).Updates(
			map[string]interface{}{"state": common.DATA_SOURCE_STATE_EXCEPTION},
		)
	}
	mysql.Db.Delete(&dataSource)

	return map[string]string{"LCUUID": lcuuid}, err
}

func CallRozeAPIAddRP(ip string, dataSource, baseDataSource mysql.DataSource, rozePort int) error {
	url := fmt.Sprintf("http://%s:%d/v1/rpadd/", common.GetCURLIP(ip), rozePort)
	// For compatibility, it used to be called name, but now it is renamed data_table.
	name := addPrefixIfNeeded(dataSource.DataTable)
	baseRP := addPrefixIfNeeded(baseDataSource.DataTable)
	body := map[string]interface{}{
		"name":                  name,
		"db":                    "vtap_" + dataSource.TsdbType,
		"base-rp":               baseRP,
		"summable-metrics-op":   strings.ToLower(dataSource.SummableMetricsOperator),
		"unsummable-metrics-op": strings.ToLower(dataSource.UnSummableMetricsOperator),
		"interval":              dataSource.Interval / common.INTERVAL_1MINUTE,
		"retention-time":        dataSource.RetentionTime,
	}
	log.Infof("call add data_source, url: %s, body: %v", url, body)
	_, err := common.CURLPerform("POST", url, body)
	return err
}

func CallRozeAPIModRP(ip string, dataSource mysql.DataSource, rozePort int) error {
	url := fmt.Sprintf("http://%s:%d/v1/rpmod/", common.GetCURLIP(ip), rozePort)
	db := dataSource.TsdbType
	// do compatible
	if containsValue([]string{common.DATA_SOURCE_L4_FLOW_LOG, common.DATA_SOURCE_L7_FLOW_LOG,
		common.DATA_SOURCE_L4_PACKAGE, common.DATA_SOURCE_L7_PACKAGE}, dataSource.TsdbType) {
		db = DATA_TABLE_PREFIX + "." + db
	}
	if dataSource.TsdbType == common.DATA_SOURCE_APP || dataSource.TsdbType == common.DATA_SOURCE_FLOW {
		db = "vtap_" + db
	}
	// For compatibility, it used to be called name, but now it is renamed data_table.
	name := addPrefixIfNeeded(dataSource.DataTable)
	body := map[string]interface{}{
		"name":           name,
		"db":             db,
		"retention-time": dataSource.RetentionTime,
	}
	log.Infof("call mod data_source, url: %s, body: %v", url, body)
	_, err := common.CURLPerform("PATCH", url, body)
	return err
}

func CallRozeAPIDelRP(ip string, dataSource mysql.DataSource, rozePort int) error {
	url := fmt.Sprintf("http://%s:%d/v1/rpdel/", common.GetCURLIP(ip), rozePort)
	// For compatibility, it used to be called name, but now it is renamed data_table.
	name := addPrefixIfNeeded(dataSource.DataTable)
	body := map[string]interface{}{
		"name": name,
		"db":   "vtap_" + dataSource.TsdbType,
	}
	log.Infof("call del data_source, url: %s, body: %v", url, body)
	_, err := common.CURLPerform("DELETE", url, body)
	return err
}

// addPrefixIfNeeded add a prefix to data_table and tsdb_type for compatibility,
// when they are one of l4_flow_log, l7_flow_log, l4_packet or l7_packet need to add prefix.
func addPrefixIfNeeded(dataTable string) string {
	if containsValue(DATA_TABLE_TO_ADD_PREFIX, dataTable) {
		return DATA_TABLE_PREFIX + "." + dataTable
	}
	return dataTable
}

func containsValue(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

func ConfigAnalyzerDataSource(ip string) error {
	var dataSources []mysql.DataSource
	var err error

	mysql.Db.Find(&dataSources)
	idToDataSource := make(map[int]mysql.DataSource)
	for _, dataSource := range dataSources {
		idToDataSource[dataSource.ID] = dataSource
	}

	for _, dataSource := range dataSources {
		// default data_source modify retention policy
		// custom data_source add retention policy
		sort.Strings(DATA_SOURCE_DEFAULT_DATA_TABLE)
		index := sort.SearchStrings(DATA_SOURCE_DEFAULT_DATA_TABLE, dataSource.DataTable)
		if index < len(DATA_SOURCE_DEFAULT_DATA_TABLE) && DATA_SOURCE_DEFAULT_DATA_TABLE[index] == dataSource.DataTable {
			if CallRozeAPIModRP(ip, dataSource, common.ROZE_PORT) != nil {
				errMsg := fmt.Sprintf(
					"config analyzer (%s) mod data_source (%s) failed", ip, dataSource.DataTable,
				)
				log.Error(errMsg)
				err = NewError(common.SERVER_ERROR, errMsg)
				continue
			}
		} else {
			baseDataSource, ok := idToDataSource[dataSource.BaseDataSourceID]
			if !ok {
				errMsg := fmt.Sprintf("base data_source (%d) not exist", dataSource.BaseDataSourceID)
				log.Error(errMsg)
				err = NewError(common.SERVER_ERROR, errMsg)
				continue
			}
			if CallRozeAPIAddRP(ip, dataSource, baseDataSource, common.ROZE_PORT) != nil {
				errMsg := fmt.Sprintf(
					"config analyzer (%s) add data_source (%s) failed", ip, dataSource.DataTable,
				)
				log.Error(errMsg)
				err = NewError(common.SERVER_ERROR, errMsg)
				continue
			}
		}
		log.Infof(
			"config analyzer (%s) mod data_source (%s) complete", ip, dataSource.DataTable,
		)
	}

	return err
}
