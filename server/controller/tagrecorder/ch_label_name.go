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
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChPrometheusLabelName struct {
	UpdaterComponent[mysql.ChPrometheusLabelName, IDKey]
}

func NewChPrometheusLabelName() *ChPrometheusLabelName {
	updater := &ChPrometheusLabelName{
		newUpdaterComponent[mysql.ChPrometheusLabelName, IDKey](
			RESOURCE_TYPE_CH_LABEL_NAME,
		),
	}

	updater.updaterDG = updater
	return updater
}

func (l *ChPrometheusLabelName) generateNewData() (map[IDKey]mysql.ChPrometheusLabelName, bool) {
	var prometheusLabelName []mysql.PrometheusLabelName

	err := mysql.Db.Unscoped().Find(&prometheusLabelName).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPrometheusLabelName)
	for _, labelName := range prometheusLabelName {
		keyToItem[IDKey{ID: labelName.ID}] = mysql.ChPrometheusLabelName{
			ID:   labelName.ID,
			Name: labelName.Name,
		}
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
