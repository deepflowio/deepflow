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

type ChAlarmPolicy struct {
	UpdaterComponent[mysql.ChAlarmPolicy, IDKey]
}

func NewChAlarmPolicy() *ChAlarmPolicy {
	updater := &ChAlarmPolicy{
		newUpdaterComponent[mysql.ChAlarmPolicy, IDKey](
			RESOURCE_TYPE_CH_ALARM_POLICY,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (p *ChAlarmPolicy) generateNewData(db *mysql.DB) (map[IDKey]mysql.ChAlarmPolicy, bool) {
	log.Infof("generate data for %s", p.resourceTypeName)
	var alarmPolicys []mysql.AlarmPolicy
	err := db.Unscoped().Find(&alarmPolicys).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChAlarmPolicy)
	for _, alarmPolicy := range alarmPolicys {
		keyToItem[IDKey{ID: alarmPolicy.ID}] = mysql.ChAlarmPolicy{
			ID:     alarmPolicy.ID,
			Name:   alarmPolicy.Name,
			UserID: alarmPolicy.UserID,
			TeamID: alarmPolicy.TeamID,
		}
	}
	return keyToItem, true
}

func (p *ChAlarmPolicy) generateKey(dbItem mysql.ChAlarmPolicy) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChAlarmPolicy) generateUpdateInfo(oldItem, newItem mysql.ChAlarmPolicy) (map[string]interface{}, bool) {
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
