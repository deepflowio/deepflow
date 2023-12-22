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

type ChPrometheusLabelName struct {
	UpdaterBase[mysql.ChPrometheusLabelName, IDKey]
}

func NewChPrometheusLabelName() *ChPrometheusLabelName {
	updater := &ChPrometheusLabelName{
		UpdaterBase[mysql.ChPrometheusLabelName, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_LABEL_NAME,
		},
	}

	updater.dataGenerator = updater
	return updater
}

func (l *ChPrometheusLabelName) getNewData() ([]mysql.ChPrometheusLabelName, bool) {
	var prometheusLabelName []mysql.PrometheusLabelName

	err := mysql.Db.Unscoped().Find(&prometheusLabelName).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	items := make([]mysql.ChPrometheusLabelName, len(prometheusLabelName))
	for i, labelName := range prometheusLabelName {
		items[i] = mysql.ChPrometheusLabelName{
			ID:   labelName.ID,
			Name: labelName.Name,
		}
	}
	return items, true
}

func (l *ChPrometheusLabelName) generateNewData() (map[IDKey]mysql.ChPrometheusLabelName, bool) {
	items, ok := l.getNewData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPrometheusLabelName, len(items))
	for _, item := range items {
		keyToItem[IDKey{item.ID}] = item
	}
	return keyToItem, true
}

func (l *ChPrometheusLabelName) generateKey(dbItem mysql.ChPrometheusLabelName) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (l *ChPrometheusLabelName) generateUpdateInfo(oldItem, newItem mysql.ChPrometheusLabelName) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
