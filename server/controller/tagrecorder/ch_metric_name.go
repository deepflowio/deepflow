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

type ChPrometheusMetricName struct {
	UpdaterBase[mysql.ChPrometheusMetricName, IDKey]
}

func NewChPrometheusMetricNames() *ChPrometheusMetricName {
	updater := &ChPrometheusMetricName{
		UpdaterBase[mysql.ChPrometheusMetricName, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_METRIC_NAME,
		},
	}

	updater.dataGenerator = updater
	return updater
}

func (l *ChPrometheusMetricName) getNewData() ([]mysql.ChPrometheusMetricName, bool) {
	var prometheusMetricName []mysql.PrometheusMetricName

	err := mysql.Db.Unscoped().Find(&prometheusMetricName).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	items := make([]mysql.ChPrometheusMetricName, len(prometheusMetricName))
	for i, metricName := range prometheusMetricName {
		items[i] = mysql.ChPrometheusMetricName{
			ID:   metricName.ID,
			Name: metricName.Name,
		}
	}
	return items, true
}
func (l *ChPrometheusMetricName) generateNewData() (map[IDKey]mysql.ChPrometheusMetricName, bool) {
	items, ok := l.getNewData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPrometheusMetricName, len(items))
	for _, item := range items {
		keyToItem[IDKey{ID: item.ID}] = item
	}
	return keyToItem, true
}

func (l *ChPrometheusMetricName) generateKey(dbItem mysql.ChPrometheusMetricName) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (l *ChPrometheusMetricName) generateUpdateInfo(oldItem, newItem mysql.ChPrometheusMetricName) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
