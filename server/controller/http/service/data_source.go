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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

type DataSource struct {
	cfg *config.ControllerConfig

	resourceAccess *ResourceAccess
	ipToController map[string]*metadbmodel.Controller
}

func NewDataSource(userInfo *httpcommon.UserInfo, cfg *config.ControllerConfig) *DataSource {
	dataSource := &DataSource{
		cfg:            cfg,
		resourceAccess: &ResourceAccess{Fpermit: cfg.FPermit, UserInfo: userInfo},
	}

	dataSource.generateIPToController()
	return dataSource
}

func NewDataSourceWithIngesterAPIConfig(userInfo *httpcommon.UserInfo, cfg common.IngesterApi) *DataSource {
	dataSource := &DataSource{
		cfg: &config.ControllerConfig{
			IngesterApi: cfg,
		},
		resourceAccess: &ResourceAccess{UserInfo: userInfo},
	}
	if err := dataSource.generateIPToController(); err != nil {
		log.Warning(err)
	}
	return dataSource
}

func (d *DataSource) generateIPToController() error {
	db, err := metadb.GetDB(d.resourceAccess.UserInfo.ORGID)
	if err != nil {
		return err
	}
	var controllers []metadbmodel.Controller
	if err = db.Find(&controllers).Error; err != nil {
		return err
	}
	ipToController := make(map[string]*metadbmodel.Controller)
	for i, controller := range controllers {
		ipToController[controller.IP] = &controllers[i]
	}
	d.ipToController = ipToController
	return nil
}

var DEFAULT_DATA_SOURCE_DISPLAY_NAMES = []string{
	"网络-指标（秒级）", "网络-指标（分钟级）", "网络-指标（小时级）", "网络-指标（天级）", // flow_metrics.network*
	"网络-流日志",                                             // flow_log.l4_flow_log
	"应用-指标（秒级）", "应用-指标（分钟级）", "应用-指标（小时级）", "应用-指标（天级）", // flow_metrics.application*
	"应用-调用日志",       // flow_log.l7_flow_log
	"网络-TCP 时序数据",   // flow_log.l4_packet
	"网络-PCAP 数据",    // flow_log.l7_packet
	"租户侧监控数据",       //  deepflow_tenant.*
	"管理侧监控数据",       // deepflow_admin.*
	"外部指标数据",        // ext_metrics.*
	"Prometheus 数据", // prometheus.*
	"事件-资源变更事件",     // event.event
	"事件-IO 事件",      // event.perf_event
	"事件-告警事件",       // event.alert_event
	"应用-性能剖析",       // profile.in_process
	"网络-网络策略",       // flow_metrics.traffic_policy
	"日志-日志数据",       // application_log.log
}

func (d *DataSource) GetDataSources(orgID int, filter map[string]interface{}, specCfg *config.Specification) (resp []model.DataSource, err error) {
	dbInfo, err := metadb.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB
	var baseDataSources []metadbmodel.DataSource
	if err := db.Find(&baseDataSources).Error; err != nil {
		return nil, err
	}
	idToDisplayName := make(map[int]string)
	for _, baseDataSource := range baseDataSources {
		idToDisplayName[baseDataSource.ID] = baseDataSource.DisplayName
	}

	var response []model.DataSource
	for _, dataSource := range baseDataSources {
		// filter
		if _, ok := filter["lcuuid"]; ok {
			if dataSource.Lcuuid != filter["lcuuid"] {
				continue
			}
		}
		if t, ok := filter["type"]; ok {
			var collection string
			switch t {
			case "application":
				collection = "flow_metrics.application*"
			case "network":
				collection = "flow_metrics.network*"
			case "deepflow_tenant":
				collection = "deepflow_tenant.*"
			case "deepflow_admin":
				collection = "deepflow_admin.*"
			case "ext_metrics":
				collection = "ext_metrics.*"
			case "prometheus":
				collection = "prometheus.*"
			case "traffic_policy":
				collection = "flow_metrics.traffic_policy"
			default:
				return nil, fmt.Errorf("not support type(%s)", t)
			}
			if dataSource.DataTableCollection != collection {
				continue
			}
		}
		if name, ok := filter["name"]; ok {
			interval_time := convertNameToInterval(name.(string))
			if interval_time != 0 && interval_time != dataSource.IntervalTime {
				continue
			}
		}

		name, err := getName(dataSource.IntervalTime, dataSource.DataTableCollection)
		if err != nil {
			log.Error(err, dbInfo.LogPrefixORGID)
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
			IntervalTime:              dataSource.IntervalTime,
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
			if dataSource.DataTableCollection == "deepflow_tenant.*" ||
				dataSource.DataTableCollection == "deepflow_admin.*" {
				dataSourceResp.IntervalTime = common.DATA_SOURCE_DEEPFLOW_SYSTEM_INTERVAL
			}
			if dataSource.DataTableCollection == "ext_metrics.*" {
				dataSourceResp.IntervalTime = specCfg.DataSourceExtMetricsInterval
			}
			if dataSource.DataTableCollection == "prometheus.*" {
				dataSourceResp.IntervalTime = specCfg.DataSourcePrometheusInterval
			}
		}

		response = append(response, dataSourceResp)
	}
	return response, nil
}

func (d *DataSource) CreateDataSource(orgID int, dataSourceCreate *model.DataSourceCreate) (model.DataSource, error) {
	lcuuid := uuid.New().String()
	if err := d.resourceAccess.CanAddResource(common.DEFAULT_TEAM_ID, common.SET_RESOURCE_TYPE_DATA_SOURCE, lcuuid); err != nil {
		return model.DataSource{}, err
	}

	dbInfo, err := metadb.GetDB(orgID)
	if err != nil {
		return model.DataSource{}, err
	}
	db := dbInfo.DB
	var dataSource metadbmodel.DataSource
	var baseDataSource metadbmodel.DataSource
	var dataSourceCount int64

	if ret := db.Where(
		map[string]interface{}{
			"data_table_collection": dataSourceCreate.DataTableCollection,
			"interval_time":         dataSourceCreate.IntervalTime,
		},
	).First(&dataSource); ret.Error == nil {
		return model.DataSource{}, response.ServiceError(
			httpcommon.RESOURCE_ALREADY_EXIST,
			fmt.Sprintf("data_source with same effect(data_table_collection: %v, interval_time: %v) already exists",
				dataSourceCreate.DataTableCollection, dataSourceCreate.IntervalTime),
		)
	}

	if dataSourceCreate.RetentionTime > d.cfg.Spec.DataSourceRetentionTimeMax {
		return model.DataSource{}, response.ServiceError(
			httpcommon.PARAMETER_ILLEGAL,
			fmt.Sprintf("data_source retention_time should le %d", d.cfg.Spec.DataSourceRetentionTimeMax),
		)
	}

	if err := db.Model(&model.DataSource{}).Count(&dataSourceCount).Error; err != nil {
		return model.DataSource{}, err
	}
	if int(dataSourceCount) >= d.cfg.Spec.DataSourceMax {
		return model.DataSource{}, response.ServiceError(
			httpcommon.RESOURCE_NUM_EXCEEDED,
			fmt.Sprintf("data_source count exceeds (limit %d)", d.cfg.Spec.DataSourceMax),
		)
	}

	if ret := db.Where("id = ?", dataSourceCreate.BaseDataSourceID).First(&baseDataSource); ret.Error != nil {
		return model.DataSource{}, response.ServiceError(
			httpcommon.PARAMETER_ILLEGAL,
			fmt.Sprintf("base data_source (%d) not exist", dataSourceCreate.BaseDataSourceID),
		)
	}

	if baseDataSource.DataTableCollection != dataSourceCreate.DataTableCollection || baseDataSource.IntervalTime == common.INTERVAL_1DAY {
		return model.DataSource{}, response.ServiceError(
			httpcommon.PARAMETER_ILLEGAL,
			"base data_source tsdb_type should the same as tsdb and interval_time should ne 1 day",
		)
	}

	if baseDataSource.IntervalTime >= dataSourceCreate.IntervalTime {
		return model.DataSource{}, response.ServiceError(
			httpcommon.PARAMETER_ILLEGAL, "interval_time should gt base data_source interval_time",
		)
	}

	if baseDataSource.SummableMetricsOperator == "Sum" && dataSourceCreate.SummableMetricsOperator != "Sum" {
		return model.DataSource{}, response.ServiceError(
			httpcommon.PARAMETER_ILLEGAL,
			"summable_metrics_operator only support Sum, if base data_source summable_metrics_operator is Sum",
		)
	}

	if (baseDataSource.SummableMetricsOperator == "Max" || baseDataSource.SummableMetricsOperator == "Min") &&
		!(dataSourceCreate.SummableMetricsOperator == "Max" || dataSourceCreate.SummableMetricsOperator == "Min") {
		return model.DataSource{}, response.ServiceError(
			httpcommon.PARAMETER_ILLEGAL,
			"summable_metrics_operator only support Max/Min, if base data_source summable_metrics_operator is Max/Min",
		)
	}

	dataSource = metadbmodel.DataSource{}

	dataSource.Lcuuid = lcuuid
	dataSource.DisplayName = dataSourceCreate.DisplayName
	dataSource.DataTableCollection = dataSourceCreate.DataTableCollection
	dataSource.BaseDataSourceID = dataSourceCreate.BaseDataSourceID
	dataSource.IntervalTime = dataSourceCreate.IntervalTime
	dataSource.RetentionTime = dataSourceCreate.RetentionTime
	dataSource.SummableMetricsOperator = dataSourceCreate.SummableMetricsOperator
	dataSource.UnSummableMetricsOperator = dataSourceCreate.UnSummableMetricsOperator
	if err := db.Create(&dataSource).Error; err != nil {
		return model.DataSource{}, err
	}

	// 调用ingester API配置clickhouse
	var analyzers []metadbmodel.Analyzer
	if err := db.Find(&analyzers).Error; err != nil {
		return model.DataSource{}, err
	}

	var errStrs []string
	for _, analyzer := range analyzers {
		if ingesterErr := d.CallIngesterAPIAddRP(orgID, analyzer.IP, dataSource, baseDataSource); ingesterErr != nil {
			errStr := fmt.Sprintf(
				"failed to config analyzer (name:%s, ip:%s) add data_source(%s), error: %s",
				analyzer.Name, analyzer.IP, dataSource.DisplayName, ingesterErr.Error(),
			)
			errStrs = append(errStrs, errStr)
			continue
		}
		log.Infof(
			"config analyzer (%s) add data_source (%s) complete",
			analyzer.IP, dataSource.DisplayName, dbInfo.LogPrefixORGID, dbInfo.LogPrefixORGID,
		)
	}
	if len(errStrs) > 0 {
		errMsg := strings.Join(errStrs, ".") + "."
		err = response.ServiceError(httpcommon.PARTIAL_CONTENT, errMsg)
		log.Error(errMsg, dbInfo.LogPrefixORGID)
	}

	if err != nil {
		if err := db.Model(&dataSource).Updates(
			map[string]interface{}{"state": common.DATA_SOURCE_STATE_EXCEPTION},
		).Error; err != nil {
			return model.DataSource{}, err
		}
	}

	response, _ := d.GetDataSources(orgID, map[string]interface{}{"lcuuid": lcuuid}, nil)
	return response[0], err
}

func (d *DataSource) UpdateDataSource(orgID int, lcuuid string, dataSourceUpdate model.DataSourceUpdate) (model.DataSource, error) {
	dbInfo, err := metadb.GetDB(orgID)
	if err != nil {
		return model.DataSource{}, err
	}
	db := dbInfo.DB
	var dataSource metadbmodel.DataSource
	if ret := db.Where("lcuuid = ?", lcuuid).First(&dataSource); ret.Error != nil {
		return model.DataSource{}, response.ServiceError(
			httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("data_source (%s) not found", lcuuid),
		)
	}

	if err := d.resourceAccess.CanUpdateResource(common.DEFAULT_TEAM_ID,
		common.SET_RESOURCE_TYPE_DATA_SOURCE, dataSource.Lcuuid, nil); err != nil {
		return model.DataSource{}, err
	}

	if dataSourceUpdate.RetentionTime != nil &&
		*dataSourceUpdate.RetentionTime > d.cfg.Spec.DataSourceRetentionTimeMax {
		return model.DataSource{}, response.ServiceError(
			httpcommon.INVALID_POST_DATA,
			fmt.Sprintf("data_source retention_time should le %d", d.cfg.Spec.DataSourceRetentionTimeMax),
		)
	}
	// can not update default data source
	if dataSourceUpdate.DisplayName != nil &&
		utils.Find(DEFAULT_DATA_SOURCE_DISPLAY_NAMES, dataSource.DisplayName) {
		return model.DataSource{}, response.ServiceError(
			httpcommon.INVALID_POST_DATA,
			fmt.Sprintf("can not update default data source(name: %s)", dataSource.DisplayName),
		)
	}
	// can not update name to default data source name
	if dataSourceUpdate.DisplayName != nil &&
		utils.Find(DEFAULT_DATA_SOURCE_DISPLAY_NAMES, *dataSourceUpdate.DisplayName) {
		return model.DataSource{}, response.ServiceError(
			httpcommon.INVALID_POST_DATA,
			fmt.Sprintf("can not update name to default data source name(%s)", *dataSourceUpdate.DisplayName),
		)
	}

	if dataSourceUpdate.DisplayName != nil {
		if err := db.Model(&dataSource).
			Updates(map[string]interface{}{"display_name": *dataSourceUpdate.DisplayName}).Error; err != nil {
			return model.DataSource{}, err
		}
	}
	// only update display nmae
	if dataSourceUpdate.DisplayName != nil && dataSourceUpdate.RetentionTime == nil {
		response, _ := d.GetDataSources(orgID, map[string]interface{}{"lcuuid": lcuuid}, nil)
		return response[0], nil
	}

	oldRetentionTime := dataSource.RetentionTime
	if dataSourceUpdate.RetentionTime != nil {
		dataSource.RetentionTime = *dataSourceUpdate.RetentionTime
	}

	// 调用roze API配置clickhouse
	var analyzers []metadbmodel.Analyzer
	if err := db.Find(&analyzers).Error; err != nil {
		return model.DataSource{}, err
	}
	var errs []error
	for _, analyzer := range analyzers {
		err = d.CallIngesterAPIModRP(orgID, analyzer.IP, dataSource)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"failed to config analyzer (name: %s, ip:%s) update data_source (%s) error: %w",
				analyzer.Name, analyzer.IP, dataSource.DisplayName, err,
			))
			continue
		}
		log.Infof("config analyzer (%s) mod data_source (%s) complete, retention time change: %ds -> %ds",
			analyzer.IP, dataSource.DisplayName, oldRetentionTime, dataSource.RetentionTime, dbInfo.LogPrefixORGID)
	}

	if len(errs) == 0 {
		if err := db.Model(&dataSource).Updates(
			map[string]interface{}{
				"state":          common.DATA_SOURCE_STATE_NORMAL,
				"retention_time": dataSource.RetentionTime,
			},
		).Error; err != nil {
			return model.DataSource{}, err
		}
		log.Infof("update data_source (%s), retention time change: %ds -> %ds",
			dataSource.DisplayName, oldRetentionTime, dataSource.RetentionTime, dbInfo.LogPrefixORGID)
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
			err = response.ServiceError(httpcommon.PARTIAL_CONTENT, errMsg)
			break
		}
	}

	for _, e := range errs {
		if errors.Is(e, httpcommon.ErrorPending) {
			warnMsg := fmt.Sprintf("pending %s", e.Error())
			log.Warning(warnMsg, dbInfo.LogPrefixORGID)
			err = response.ServiceError(httpcommon.CONFIG_PENDING, warnMsg)
			break
		}
	}

	response, _ := d.GetDataSources(orgID, map[string]interface{}{"lcuuid": lcuuid}, nil)
	return response[0], err
}

func (d *DataSource) DeleteDataSource(orgID int, lcuuid string) (map[string]string, error) {
	dbInfo, err := metadb.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB
	var dataSource metadbmodel.DataSource
	var baseDataSource metadbmodel.DataSource

	if ret := db.Where("lcuuid = ?", lcuuid).First(&dataSource); ret.Error != nil {
		return map[string]string{}, response.ServiceError(
			httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("data_source (%s) not found", lcuuid),
		)
	}

	if err := d.resourceAccess.CanDeleteResource(common.DEFAULT_TEAM_ID,
		common.SET_RESOURCE_TYPE_DATA_SOURCE, dataSource.Lcuuid); err != nil {
		return nil, err
	}

	// 默认数据源禁止删除
	sort.Strings(DEFAULT_DATA_SOURCE_DISPLAY_NAMES)
	index := sort.SearchStrings(DEFAULT_DATA_SOURCE_DISPLAY_NAMES, dataSource.DisplayName)
	if index < len(DEFAULT_DATA_SOURCE_DISPLAY_NAMES) && DEFAULT_DATA_SOURCE_DISPLAY_NAMES[index] == dataSource.DisplayName {
		return map[string]string{}, response.ServiceError(
			httpcommon.INVALID_POST_DATA, "Not support delete default data_source",
		)
	}

	// 被其他数据源引用的数据源禁止删除
	if ret := db.Where("base_data_source_id = ?", dataSource.ID).First(&baseDataSource); ret.Error == nil {
		return map[string]string{}, response.ServiceError(
			httpcommon.INVALID_POST_DATA,
			fmt.Sprintf("data_source (%s) is used by other data_source", dataSource.DisplayName),
		)
	}

	log.Infof("delete data_source (%s)", dataSource.DisplayName, dbInfo.LogPrefixORGID)

	// 调用ingester API配置clickhouse
	var analyzers []metadbmodel.Analyzer
	if err := db.Find(&analyzers).Error; err != nil {
		return nil, err
	}

	var errStrs []string
	for _, analyzer := range analyzers {
		if ingesterErr := d.CallIngesterAPIDelRP(orgID, analyzer.IP, dataSource); ingesterErr != nil {
			errStr := fmt.Sprintf(
				"failed to config analyzer (name: %s, ip:%s) delete data_source (%s) error(%s)",
				analyzer.Name, analyzer.IP, dataSource.DisplayName, ingesterErr.Error(),
			)
			errStrs = append(errStrs, errStr)
			continue
		}
		log.Infof(
			"config analyzer (%s) del data_source (%s) complete",
			analyzer.IP, dataSource.DisplayName, dbInfo.LogPrefixORGID,
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
		err = response.ServiceError(httpcommon.SERVER_ERROR, errMsg)
		log.Error(errMsg, dbInfo.LogPrefixORGID)
	}
	if e := db.Delete(&dataSource).Error; e != nil {
		return nil, e
	}

	return map[string]string{"LCUUID": lcuuid}, err
}

func (d *DataSource) CallIngesterAPIAddRP(orgID int, ip string, dataSource, baseDataSource metadbmodel.DataSource) error {
	var name, baseName string
	var err error
	if name, err = getName(dataSource.IntervalTime, dataSource.DataTableCollection); err != nil {
		return err
	}
	if baseName, err = getName(baseDataSource.IntervalTime, baseDataSource.DataTableCollection); err != nil {
		return err
	}
	body := map[string]interface{}{
		common.INGESTER_BODY_ORG_ID: orgID,
		"name":                      name,
		"db":                        getTableName(dataSource.DataTableCollection),
		"base-rp":                   baseName,
		"summable-metrics-op":       strings.ToLower(dataSource.SummableMetricsOperator),
		"unsummable-metrics-op":     strings.ToLower(dataSource.UnSummableMetricsOperator),
		"interval":                  dataSource.IntervalTime / common.INTERVAL_1MINUTE,
		"retention-time":            dataSource.RetentionTime,
	}
	if len(d.ipToController) == 0 {
		log.Warningf("get ip to controller nil", logger.NewORGPrefix(orgID))
	}
	port := d.cfg.IngesterApi.NodePort
	if controller, ok := d.ipToController[ip]; ok {
		if controller.NodeType == common.CONTROLLER_NODE_TYPE_MASTER && len(controller.PodIP) != 0 {
			ip = controller.PodIP
			port = d.cfg.IngesterApi.Port
		}
	}
	url := fmt.Sprintf("http://%s:%d/v1/rpadd/", common.GetCURLIP(ip), port)
	log.Infof("call add data_source, url: %s, body: %v", url, body, logger.NewORGPrefix(orgID))
	_, err = common.CURLPerform("POST", url, body, common.WithORGHeader(strconv.Itoa(orgID)))
	if err != nil && !(errors.Is(err, httpcommon.ErrorPending) || errors.Is(err, httpcommon.ErrorFail)) {
		err = fmt.Errorf("%w, %s", httpcommon.ErrorFail, err.Error())
	}
	return err
}

func (d *DataSource) CallIngesterAPIModRP(orgID int, ip string, dataSource metadbmodel.DataSource) error {
	name, err := getName(dataSource.IntervalTime, dataSource.DataTableCollection)
	if err != nil {
		return err
	}
	body := map[string]interface{}{
		common.INGESTER_BODY_ORG_ID: orgID,
		"name":                      name,
		"db":                        getTableName(dataSource.DataTableCollection),
		"retention-time":            dataSource.RetentionTime,
	}
	if len(d.ipToController) == 0 {
		log.Warningf("get ip to controller nil", logger.NewORGPrefix(orgID))
	}
	port := d.cfg.IngesterApi.NodePort
	if controller, ok := d.ipToController[ip]; ok {
		if controller.NodeType == common.CONTROLLER_NODE_TYPE_MASTER && len(controller.PodIP) != 0 {
			ip = controller.PodIP
			port = d.cfg.IngesterApi.Port
		}
	}
	url := fmt.Sprintf("http://%s:%d/v1/rpmod/", common.GetCURLIP(ip), port)
	log.Infof("call mod data_source, url: %s, body: %v", url, body, logger.NewORGPrefix(orgID))
	_, err = common.CURLPerform("PATCH", url, body, common.WithORGHeader(strconv.Itoa(orgID)))
	if err != nil && !(errors.Is(err, httpcommon.ErrorPending) || errors.Is(err, httpcommon.ErrorFail)) {
		err = fmt.Errorf("%w, %s", httpcommon.ErrorFail, err.Error())
	}
	return err
}

func (d *DataSource) CallIngesterAPIDelRP(orgID int, ip string, dataSource metadbmodel.DataSource) error {
	name, err := getName(dataSource.IntervalTime, dataSource.DataTableCollection)
	if err != nil {
		return err
	}
	body := map[string]interface{}{
		common.INGESTER_BODY_ORG_ID: orgID,
		"name":                      name,
		"db":                        getTableName(dataSource.DataTableCollection),
	}
	if len(d.ipToController) == 0 {
		log.Warningf("get ip to controller nil", logger.NewORGPrefix(orgID))
	}
	port := d.cfg.IngesterApi.NodePort
	if controller, ok := d.ipToController[ip]; ok {
		if controller.NodeType == common.CONTROLLER_NODE_TYPE_MASTER && len(controller.PodIP) != 0 {
			ip = controller.PodIP
			port = d.cfg.IngesterApi.Port
		}
	}
	url := fmt.Sprintf("http://%s:%d/v1/rpdel/", common.GetCURLIP(ip), port)
	log.Infof("call del data_source, url: %s, body: %v", url, body, logger.NewORGPrefix(orgID))
	_, err = common.CURLPerform("DELETE", url, body, common.WithORGHeader(strconv.Itoa(orgID)))
	if err != nil && !(errors.Is(err, httpcommon.ErrorPending) || errors.Is(err, httpcommon.ErrorFail)) {
		err = fmt.Errorf("%w, %s", httpcommon.ErrorFail, err.Error())
	}
	return err
}

func getName(interval_time int, collection string) (string, error) {
	switch interval_time {
	case 0:
		// return value: flow_log.l4_flow_log, flow_log.l7_flow_log,
		// flow_log.l4_packet, flow_log.l7_packet,
		// deepflow_tenant, deepflow_admin, ext_metrics, prometheus,
		// event.event, event.perf_event, event.alert_event
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
		return "", fmt.Errorf("get name error, interval_time does not support value: %d", interval_time)
	}
}

func convertNameToInterval(name string) (interval_time int) {
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
		log.Warningf("unsupported name: %s", name)
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

func (d *DataSource) ConfigAnalyzerDataSource(orgID int, ip string) error {
	var dataSources []metadbmodel.DataSource
	var err error

	dbInfo, err := metadb.GetDB(orgID)
	if err != nil {
		return err
	}
	db := dbInfo.DB
	if err := db.Find(&dataSources).Error; err != nil {
		return err
	}
	idToDataSource := make(map[int]metadbmodel.DataSource)
	for _, dataSource := range dataSources {
		idToDataSource[dataSource.ID] = dataSource
	}

	for _, dataSource := range dataSources {
		// default data_source modify retention policy
		// custom data_source add retention policy
		sort.Strings(DEFAULT_DATA_SOURCE_DISPLAY_NAMES)
		index := sort.SearchStrings(DEFAULT_DATA_SOURCE_DISPLAY_NAMES, dataSource.DisplayName)
		if index < len(DEFAULT_DATA_SOURCE_DISPLAY_NAMES) && DEFAULT_DATA_SOURCE_DISPLAY_NAMES[index] == dataSource.DisplayName {
			if d.CallIngesterAPIModRP(orgID, ip, dataSource) != nil {
				errMsg := fmt.Sprintf(
					"config analyzer (%s) mod data_source (%s) failed", ip, dataSource.DisplayName,
				)
				log.Error(errMsg, dbInfo.LogPrefixORGID)
				err = response.ServiceError(httpcommon.SERVER_ERROR, errMsg)
				continue
			}
		} else {
			baseDataSource, ok := idToDataSource[dataSource.BaseDataSourceID]
			if !ok {
				errMsg := fmt.Sprintf("base data_source (%d) not exist", dataSource.BaseDataSourceID)
				log.Error(errMsg, dbInfo.LogPrefixORGID)
				err = response.ServiceError(httpcommon.SERVER_ERROR, errMsg)
				continue
			}
			if d.CallIngesterAPIAddRP(orgID, ip, dataSource, baseDataSource) != nil {
				errMsg := fmt.Sprintf(
					"config analyzer (%s) add data_source (%s) failed", ip, dataSource.DisplayName,
				)
				log.Error(errMsg, dbInfo.LogPrefixORGID)
				err = response.ServiceError(httpcommon.SERVER_ERROR, errMsg)
				continue
			}
		}
		log.Infof(
			"config analyzer (%s) mod data_source (%s) complete", ip, dataSource.DisplayName, logger.NewORGPrefix(orgID),
		)
	}

	return err
}
