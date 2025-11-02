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

type ChAlarmPolicy struct {
	UpdaterComponent[mysqlmodel.ChAlarmPolicy, IDKey]
}

func NewChAlarmPolicy() *ChAlarmPolicy {
	updater := &ChAlarmPolicy{
		newUpdaterComponent[mysqlmodel.ChAlarmPolicy, IDKey](
			RESOURCE_TYPE_CH_ALARM_POLICY,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (p *ChAlarmPolicy) generateNewData(db *mysql.DB) (map[IDKey]mysqlmodel.ChAlarmPolicy, bool) {
	log.Infof("generate data for %s", p.resourceTypeName, db.LogPrefixORGID)
	var alarmPolicys []mysqlmodel.AlarmPolicy
	err := db.Unscoped().Find(&alarmPolicys).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]mysqlmodel.ChAlarmPolicy)
	for _, alarmPolicy := range alarmPolicys {
		keyToItem[IDKey{ID: alarmPolicy.ID}] = mysqlmodel.ChAlarmPolicy{
			ID:     alarmPolicy.ID,
			Name:   alarmPolicy.Name,
			UserID: alarmPolicy.UserID,
			TeamID: alarmPolicy.TeamID,
		}
	}
	return keyToItem, true
}

func (p *ChAlarmPolicy) generateKey(dbItem mysqlmodel.ChAlarmPolicy) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChAlarmPolicy) generateUpdateInfo(oldItem, newItem mysqlmodel.ChAlarmPolicy) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.UserID != newItem.UserID {
		updateInfo["user_id"] = newItem.UserID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
