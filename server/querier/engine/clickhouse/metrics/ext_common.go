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

package metrics

import (
	"context"
	"fmt"
	"slices"
	"strings"

	ctlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/client"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse/common"
)

var EXT_METRICS = map[string]*Metrics{}

func GetExtMetrics(db, table, where, queryCacheTTL, orgID string, useQueryCache bool, ctx context.Context) (map[string]*Metrics, error) {
	loadMetrics := make(map[string]*Metrics)
	if slices.Contains([]string{common.DB_NAME_DEEPFLOW_ADMIN, common.DB_NAME_DEEPFLOW_TENANT, common.DB_NAME_APPLICATION_LOG, common.DB_NAME_EXT_METRICS}, db) || slices.Contains([]string{common.TABLE_NAME_L7_FLOW_LOG, common.TABLE_NAME_EVENT, common.TABLE_NAME_FILE_EVENT}, table) {
		externalChClient := client.Client{
			Host:     config.Cfg.Clickhouse.Host,
			Port:     config.Cfg.Clickhouse.Port,
			UserName: config.Cfg.Clickhouse.User,
			Password: config.Cfg.Clickhouse.Password,
			DB:       "flow_tag",
			Context:  ctx,
		}
		var externalMetricSql string
		var tableFilter string
		var whereSql string
		externalMetricSql = "SELECT field_name, table FROM flow_tag.%s_custom_field WHERE %s field_type='metrics' %s GROUP BY field_name, table ORDER BY table, field_name ASC"
		if table != "" {
			tableFilter = fmt.Sprintf("table='%s' AND", table)
		}
		if where != "" {
			whereSql = fmt.Sprintf("AND (%s)", where)
		}
		whereSql = strings.ReplaceAll(whereSql, " name ", " field_name ")
		externalMetricSql = fmt.Sprintf(externalMetricSql, db, tableFilter, whereSql)

		externalMetricFloatRst, err := externalChClient.DoQuery(&client.QueryParams{Sql: externalMetricSql, UseQueryCache: useQueryCache, QueryCacheTTL: queryCacheTTL, ORGID: orgID})
		if err != nil {
			log.Error(err)
			return nil, err
		}
		for i, value := range externalMetricFloatRst.Values {
			tagName := value.([]interface{})[0]
			tableName := value.([]interface{})[1].(string)
			externalTag := tagName.(string)
			metrics_names_field, metrics_values_field := METRICS_ARRAY_NAME_MAP[db][0], METRICS_ARRAY_NAME_MAP[db][1]
			dbField := fmt.Sprintf("if(indexOf(%s, '%s')=0, null, %s[indexOf(%s, '%s')])", metrics_names_field, externalTag, metrics_values_field, metrics_names_field, externalTag)
			metricName := fmt.Sprintf("metrics.%s", externalTag)
			lm := NewMetrics(
				i, dbField, metricName, metricName, metricName, "", "", "", METRICS_TYPE_COUNTER,
				common.NATIVE_FIELD_CATEGORY_METRICS, []bool{true, true, true}, "", tableName, "", "", "", "", "",
			)
			loadMetrics[fmt.Sprintf("%s-%s", metricName, tableName)] = lm
		}
		if !slices.Contains([]string{common.TABLE_NAME_EVENT, common.TABLE_NAME_FILE_EVENT}, table) {
			lm := NewMetrics(
				len(loadMetrics), "metrics",
				"metrics", "metrics", "metrics", "", "", "", METRICS_TYPE_ARRAY,
				common.NATIVE_FIELD_CATEGORY_METRICS, []bool{true, true, true}, "", table, "", "", "", "", "",
			)
			loadMetrics[fmt.Sprintf("%s-%s", "metrics", table)] = lm
		}

		// native metrics
		if config.ControllerCfg.DFWebService.Enabled {
			getNativeUrl := fmt.Sprintf("http://localhost:%d/v1/native-fields/?db=%s&table_name=%s", config.ControllerCfg.ListenPort, db, table)
			resp, err := ctlcommon.CURLPerform("GET", getNativeUrl, nil, ctlcommon.WithHeader(ctlcommon.HEADER_KEY_X_ORG_ID, orgID))
			if err != nil {
				log.Errorf("request controller failed: %s, URL: %s", resp, getNativeUrl)
			} else {
				resultArray := resp.Get("DATA").MustArray()
				for i := range resultArray {
					nativeMetric := resp.Get("DATA").GetIndex(i).Get("NAME").MustString()
					displayName := resp.Get("DATA").GetIndex(i).Get("DISPLAY_NAME").MustString()
					description := resp.Get("DATA").GetIndex(i).Get("DESCRIPTION").MustString()
					fieldType := resp.Get("DATA").GetIndex(i).Get("FIELD_TYPE").MustInt()
					state := resp.Get("DATA").GetIndex(i).Get("STATE").MustInt()
					if state != common.NATIVE_FIELD_STATE_NORMAL {
						continue
					}
					if fieldType != common.NATIVE_FIELD_TYPE_METRIC {
						continue
					}
					lm := NewMetrics(
						len(loadMetrics), nativeMetric, displayName, displayName, displayName, "", "", "", METRICS_TYPE_COUNTER,
						common.NATIVE_FIELD_CATEGORY_METRICS, []bool{true, true, true}, "", table, description, description, description, "", "",
					)
					loadMetrics[fmt.Sprintf("%s-%s", nativeMetric, table)] = lm
				}
			}
		}
	}
	return loadMetrics, nil
}
