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

package tagrecorder

import (
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChPrometheusMetricAPPLabelLayout struct {
	UpdaterComponent[mysql.ChPrometheusMetricAPPLabelLayout, IDKey]
}

func NewChPrometheusMetricAPPLabelLayout() *ChPrometheusMetricAPPLabelLayout {
	updater := &ChPrometheusMetricAPPLabelLayout{
		newUpdaterComponent[mysql.ChPrometheusMetricAPPLabelLayout, IDKey](
			RESOURCE_TYPE_CH_PROMETHEUS_METRIC_APP_LABEL_LAYOUT,
		),
	}

	updater.updaterDG = updater
	return updater
}

func (l *ChPrometheusMetricAPPLabelLayout) generateNewData() (map[IDKey]mysql.ChPrometheusMetricAPPLabelLayout, bool) {
	var prometheusMetricAPPLabelLayout []mysql.PrometheusMetricAPPLabelLayout

	err := mysql.Db.Unscoped().Find(&prometheusMetricAPPLabelLayout).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPrometheusMetricAPPLabelLayout)
	for _, metricAPPLabelLayout := range prometheusMetricAPPLabelLayout {
		keyToItem[IDKey{ID: metricAPPLabelLayout.ID}] = mysql.ChPrometheusMetricAPPLabelLayout{
			ID:                  metricAPPLabelLayout.ID,
			MetricName:          metricAPPLabelLayout.MetricName,
			APPLabelName:        metricAPPLabelLayout.APPLabelName,
			APPLabelColumnIndex: metricAPPLabelLayout.APPLabelColumnIndex,
		}
	}
	return keyToItem, true
}

func (l *ChPrometheusMetricAPPLabelLayout) generateKey(dbItem mysql.ChPrometheusMetricAPPLabelLayout) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (l *ChPrometheusMetricAPPLabelLayout) generateUpdateInfo(oldItem, newItem mysql.ChPrometheusMetricAPPLabelLayout) (map[string]interface{}, bool) {
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
