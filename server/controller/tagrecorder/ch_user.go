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
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type ChUser struct {
	UpdaterComponent[metadbmodel.ChUser, IDKey]
}

func NewChUser() *ChUser {
	updater := &ChUser{
		newUpdaterComponent[metadbmodel.ChUser, IDKey](
			RESOURCE_TYPE_CH_USER,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (c *ChUser) generateNewData(db *metadb.DB) (map[IDKey]metadbmodel.ChUser, bool) {
	log.Infof("generate data for %s", c.resourceTypeName, db.LogPrefixORGID)
	var users []metadbmodel.User

	err := metadb.DefaultDB.Unscoped().Find(&users).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(c.resourceTypeName, err), db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]metadbmodel.ChUser)
	for _, user := range users {
		keyToItem[IDKey{ID: user.ID}] = metadbmodel.ChUser{
			ID:   user.ID,
			Name: user.UserName,
		}

	}
	return keyToItem, true
}

func (c *ChUser) generateKey(dbItem metadbmodel.ChUser) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (c *ChUser) generateUpdateInfo(oldItem, newItem metadbmodel.ChUser) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
