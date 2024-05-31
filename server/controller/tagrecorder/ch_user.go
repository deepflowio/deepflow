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

type ChUser struct {
	UpdaterComponent[mysql.ChUser, IDKey]
}

func NewChUser() *ChUser {
	updater := &ChUser{
		newUpdaterComponent[mysql.ChUser, IDKey](
			RESOURCE_TYPE_CH_USER,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (c *ChUser) generateNewData(db *mysql.DB) (map[IDKey]mysql.ChUser, bool) {
	log.Infof("generate data for %s", c.resourceTypeName)
	var users []mysql.User

	err := mysql.DefaultDB.Unscoped().Find(&users).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(c.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChUser)
	for _, user := range users {
		keyToItem[IDKey{ID: user.ID}] = mysql.ChUser{
			ID:   user.ID,
			Name: user.UserName,
		}

	}
	return keyToItem, true
}

func (c *ChUser) generateKey(dbItem mysql.ChUser) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (c *ChUser) generateUpdateInfo(oldItem, newItem mysql.ChUser) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
