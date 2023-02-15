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

package service

import (
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

var DEFAULT_DATA_SOURCE_NAMES = []string{"1s", "1m", "flow_log.l4", "flow_log.l7"}

func GetDataSources(filter map[string]interface{}) (resp []model.DataSource, err error) {
	var response []model.DataSource
	var dataSources []mysql.DataSource
	var baseDataSources []mysql.DataSource
	var idToDataSourceName map[int]string

	Db := mysql.Db
	if _, ok := filter["lcuuid"]; ok {
		Db = Db.Where("lcuuid = ?", filter["lcuuid"])
	}
	if _, ok := filter["type"]; ok {
		Db = Db.Where("tsdb_type = ?", filter["type"])
	}
	if _, ok := filter["name"]; ok {
		Db = Db.Where("name = ?", filter["name"])
	}
	Db.Find(&dataSources)

	mysql.Db.Find(&baseDataSources)
	idToDataSourceName = make(map[int]string)
	for _, baseDataSource := range baseDataSources {
		idToDataSourceName[baseDataSource.ID] = baseDataSource.Name
	}

	for _, dataSource := range dataSources {
		dataSourceResp := model.DataSource{
			ID:                        dataSource.ID,
			Name:                      dataSource.Name,
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
		if baseDataSourceName, ok := idToDataSourceName[dataSource.BaseDataSourceID]; ok {
			dataSourceResp.BaseDataSourceName = baseDataSourceName
		}
		sort.Strings(DEFAULT_DATA_SOURCE_NAMES)
		index := sort.SearchStrings(DEFAULT_DATA_SOURCE_NAMES, dataSource.Name)
		if index < len(DEFAULT_DATA_SOURCE_NAMES) && DEFAULT_DATA_SOURCE_NAMES[index] == dataSource.Name {
			dataSourceResp.IsDefault = true
		} else {
			dataSourceResp.IsDefault = false
		}

		response = append(response, dataSourceResp)
	}
	return response, nil
}

func CreateDataSource(dataSourceCreate model.DataSourceCreate, cfg *config.ControllerConfig) (model.DataSource, error) {
	var dataSource mysql.DataSource
	var baseDataSource mysql.DataSource
	var dataSourceCount int64
	var err error

	// TODO: 名称只能包含数字字母和下划线的校验
	if ret := mysql.Db.Where("name = ?", dataSourceCreate.Name).First(&dataSource); ret.Error == nil {
		return model.DataSource{}, NewError(
			common.RESOURCE_ALREADY_EXIST,
			fmt.Sprintf("data_source (%s) already exist", dataSourceCreate.Name),
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
	dataSource.Name = dataSourceCreate.Name
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
				"config analyzer (%s) add data_source (%s) failed", analyzer.IP, dataSource.Name,
			)
			log.Error(errMsg)
			err = NewError(common.SERVER_ERROR, errMsg)
			break
		}
		log.Infof(
			"config analyzer (%s) add data_source (%s) complete",
			analyzer.IP, dataSource.Name,
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
	var err error

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
	dataSource.RetentionTime = dataSourceUpdate.RetentionTime
	mysql.Db.Save(&dataSource)

	log.Infof("update data_source (%s)", dataSource.Name)

	// 调用roze API配置clickhouse
	var analyzers []mysql.Analyzer
	mysql.Db.Find(&analyzers)

	for _, analyzer := range analyzers {
		if CallRozeAPIModRP(analyzer.IP, dataSource, cfg.Roze.Port) != nil {
			errMsg := fmt.Sprintf(
				"config analyzer (%s) mod data_source (%s) failed", analyzer.IP, dataSource.Name,
			)
			log.Error(errMsg)
			err = NewError(common.SERVER_ERROR, errMsg)
			break
		}
		log.Infof(
			"config analyzer (%s) mod data_source (%s) complete",
			analyzer.IP, dataSource.Name,
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
	sort.Strings(DEFAULT_DATA_SOURCE_NAMES)
	index := sort.SearchStrings(DEFAULT_DATA_SOURCE_NAMES, dataSource.Name)
	if index < len(DEFAULT_DATA_SOURCE_NAMES) && DEFAULT_DATA_SOURCE_NAMES[index] == dataSource.Name {
		return map[string]string{}, NewError(
			common.INVALID_POST_DATA, "Not support delete default data_source",
		)
	}

	// 被其他数据源引用的数据源禁止删除
	if ret := mysql.Db.Where("base_data_source_id = ?", dataSource.ID).First(&baseDataSource); ret.Error == nil {
		return map[string]string{}, NewError(
			common.INVALID_POST_DATA,
			fmt.Sprintf("data_source (%s) is used by other data_source", dataSource.Name),
		)
	}

	log.Infof("delete data_source (%s)", dataSource.Name)

	// 调用roze API配置clickhouse
	var analyzers []mysql.Analyzer
	mysql.Db.Find(&analyzers)

	for _, analyzer := range analyzers {
		if CallRozeAPIDelRP(analyzer.IP, dataSource, cfg.Roze.Port) != nil {
			errMsg := fmt.Sprintf(
				"config analyzer (%s) del data_source (%s) failed", analyzer.IP, dataSource.Name,
			)
			log.Error(errMsg)
			err = NewError(common.SERVER_ERROR, errMsg)
			break
		}
		log.Infof(
			"config analyzer (%s) del data_source (%s) complete",
			analyzer.IP, dataSource.Name,
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
	body := map[string]interface{}{
		"name":                  dataSource.Name,
		"db":                    "vtap_" + dataSource.TsdbType,
		"base-rp":               baseDataSource.Name,
		"summable-metrics-op":   strings.ToLower(dataSource.SummableMetricsOperator),
		"unsummable-metrics-op": strings.ToLower(dataSource.UnSummableMetricsOperator),
		"interval":              dataSource.Interval / common.INTERVAL_1MINUTE,
		"retention-time":        dataSource.RetentionTime * (common.INTERVAL_1DAY / common.INTERVAL_1HOUR),
	}
	log.Debug(url)
	log.Debug(body)
	_, err := common.CURLPerform("POST", url, body)
	return err
}

func CallRozeAPIModRP(ip string, dataSource mysql.DataSource, rozePort int) error {
	url := fmt.Sprintf("http://%s:%d/v1/rpmod/", common.GetCURLIP(ip), rozePort)
	db := "vtap_" + dataSource.TsdbType
	switch dataSource.TsdbType {
	case common.DATA_SOURCE_L4_LOG, common.DATA_SOURCE_L7_LOG:
		db = dataSource.TsdbType
	}
	body := map[string]interface{}{
		"name":           dataSource.Name,
		"db":             db,
		"retention-time": dataSource.RetentionTime * (common.INTERVAL_1DAY / common.INTERVAL_1HOUR),
	}
	log.Debug(url)
	log.Debug(body)
	_, err := common.CURLPerform("PATCH", url, body)
	return err
}

func CallRozeAPIDelRP(ip string, dataSource mysql.DataSource, rozePort int) error {
	url := fmt.Sprintf("http://%s:%d/v1/rpdel/", common.GetCURLIP(ip), rozePort)
	body := map[string]interface{}{
		"name": dataSource.Name,
		"db":   "vtap_" + dataSource.TsdbType,
	}
	log.Debug(url)
	log.Debug(body)
	_, err := common.CURLPerform("DELETE", url, body)
	return err
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
		sort.Strings(DEFAULT_DATA_SOURCE_NAMES)
		index := sort.SearchStrings(DEFAULT_DATA_SOURCE_NAMES, dataSource.Name)
		if index < len(DEFAULT_DATA_SOURCE_NAMES) && DEFAULT_DATA_SOURCE_NAMES[index] == dataSource.Name {
			if CallRozeAPIModRP(ip, dataSource, common.ROZE_PORT) != nil {
				errMsg := fmt.Sprintf(
					"config analyzer (%s) mod data_source (%s) failed", ip, dataSource.Name,
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
					"config analyzer (%s) add data_source (%s) failed", ip, dataSource.Name,
				)
				log.Error(errMsg)
				err = NewError(common.SERVER_ERROR, errMsg)
				continue
			}
		}
		log.Infof(
			"config analyzer (%s) mod data_source (%s) complete", ip, dataSource.Name,
		)
	}

	return err
}
