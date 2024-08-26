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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
)

type ChPrometheusLabelName struct {
	UpdaterBase[mysqlmodel.ChPrometheusLabelName, IDKey]
}

func NewChPrometheusLabelName() *ChPrometheusLabelName {
	updater := &ChPrometheusLabelName{
		UpdaterBase[mysqlmodel.ChPrometheusLabelName, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_LABEL_NAME,
		},
	}

	updater.dataGenerator = updater
	return updater
}

func (l *ChPrometheusLabelName) generateNewData() (map[IDKey]mysqlmodel.ChPrometheusLabelName, bool) {
	var prometheusLabelName []mysqlmodel.PrometheusLabelName

	err := mysql.DefaultDB.Unscoped().Find(&prometheusLabelName).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err), l.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]mysqlmodel.ChPrometheusLabelName)
	for _, labelName := range prometheusLabelName {
		keyToItem[IDKey{ID: labelName.ID}] = mysqlmodel.ChPrometheusLabelName{
			ID:   labelName.ID,
			Name: labelName.Name,
		}
	}
	return keyToItem, true
}

func (l *ChPrometheusLabelName) generateKey(dbItem mysqlmodel.ChPrometheusLabelName) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (l *ChPrometheusLabelName) generateUpdateInfo(oldItem, newItem mysqlmodel.ChPrometheusLabelName) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
