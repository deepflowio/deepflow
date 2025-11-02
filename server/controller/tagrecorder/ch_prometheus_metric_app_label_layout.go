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
	mysql "github.com/deepflowio/deepflow/server/controller/db/metadb"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type ChPrometheusMetricAPPLabelLayout struct {
	UpdaterComponent[mysqlmodel.ChPrometheusMetricAPPLabelLayout, IDKey]
}

func NewChPrometheusMetricAPPLabelLayout() *ChPrometheusMetricAPPLabelLayout {
	updater := &ChPrometheusMetricAPPLabelLayout{
		newUpdaterComponent[mysqlmodel.ChPrometheusMetricAPPLabelLayout, IDKey](
			RESOURCE_TYPE_CH_PROMETHEUS_METRIC_APP_LABEL_LAYOUT,
		),
	}

	updater.updaterDG = updater
	return updater
}

func (l *ChPrometheusMetricAPPLabelLayout) generateNewData(db *mysql.DB) (map[IDKey]mysqlmodel.ChPrometheusMetricAPPLabelLayout, bool) {
	var prometheusMetricAPPLabelLayout []mysqlmodel.PrometheusMetricAPPLabelLayout

	err := db.Unscoped().Find(&prometheusMetricAPPLabelLayout).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]mysqlmodel.ChPrometheusMetricAPPLabelLayout)
	for _, metricAPPLabelLayout := range prometheusMetricAPPLabelLayout {
		keyToItem[IDKey{ID: metricAPPLabelLayout.ID}] = mysqlmodel.ChPrometheusMetricAPPLabelLayout{
			ID:                  metricAPPLabelLayout.ID,
			MetricName:          metricAPPLabelLayout.MetricName,
			APPLabelName:        metricAPPLabelLayout.APPLabelName,
			APPLabelColumnIndex: metricAPPLabelLayout.APPLabelColumnIndex,
		}
	}
	return keyToItem, true
}

func (l *ChPrometheusMetricAPPLabelLayout) generateKey(dbItem mysqlmodel.ChPrometheusMetricAPPLabelLayout) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (l *ChPrometheusMetricAPPLabelLayout) generateUpdateInfo(oldItem, newItem mysqlmodel.ChPrometheusMetricAPPLabelLayout) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.MetricName != newItem.MetricName {
		updateInfo["metric_name"] = newItem.MetricName
	}

	if oldItem.APPLabelName != newItem.APPLabelName {
		updateInfo["app_label_name"] = newItem.APPLabelName
	}

	if oldItem.APPLabelColumnIndex != newItem.APPLabelColumnIndex {
		updateInfo["app_label_column_index"] = newItem.APPLabelColumnIndex
	}

	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
