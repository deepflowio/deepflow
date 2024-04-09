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

type ChAZ struct {
	UpdaterBase[mysql.ChAZ, IDKey]
	domainLcuuidToIconID map[string]int
	resourceTypeToIconID map[IconKey]int
}

func NewChAZ(domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) *ChAZ {
	updater := &ChAZ{
		UpdaterBase[mysql.ChAZ, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_AZ,
		},
		domainLcuuidToIconID,
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (a *ChAZ) generateNewData() (map[IDKey]mysql.ChAZ, bool) {
	log.Infof("generate data for %s", a.resourceTypeName)
	var azs []mysql.AZ
	err := a.db.Unscoped().Find(&azs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(a.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChAZ)

	for _, az := range azs {
		iconID := a.domainLcuuidToIconID[az.Domain]
		if iconID == 0 {
			key := IconKey{
				NodeType: RESOURCE_TYPE_AZ,
			}
			iconID = a.resourceTypeToIconID[key]
		}
		if az.DeletedAt.Valid {
			keyToItem[IDKey{ID: az.ID}] = mysql.ChAZ{
				ID:     az.ID,
				Name:   az.Name + " (deleted)",
				IconID: iconID,
			}
		} else {
			keyToItem[IDKey{ID: az.ID}] = mysql.ChAZ{
				ID:     az.ID,
				Name:   az.Name,
				IconID: iconID,
			}
		}

	}
	return keyToItem, true
}

func (a *ChAZ) generateKey(dbItem mysql.ChAZ) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (a *ChAZ) generateUpdateInfo(oldItem, newItem mysql.ChAZ) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID && newItem.IconID != 0 {
		updateInfo["icon_id"] = newItem.IconID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
