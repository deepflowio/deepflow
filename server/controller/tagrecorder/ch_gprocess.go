/*
 * Copyright (c) 2022 Yunshan Networks
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

type ChGProcess struct {
	UpdaterBase[mysql.ChGProcess, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChGProcess(resourceTypeToIconID map[IconKey]int) *ChGProcess {
	updater := &ChGProcess{
		UpdaterBase[mysql.ChGProcess, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_GPROCESS,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChGProcess) generateNewData() (map[IDKey]mysql.ChGProcess, bool) {
	var processes []mysql.Process
	err := mysql.Db.Unscoped().Find(&processes).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChGProcess)
	for _, process := range processes {
		if process.DeletedAt.Valid {
			keyToItem[IDKey{ID: process.ID}] = mysql.ChGProcess{
				ID:     process.ID,
				Name:   process.Name + " (deleted)",
				IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_GPROCESS}],
			}
		} else {
			keyToItem[IDKey{ID: process.ID}] = mysql.ChGProcess{
				ID:     process.ID,
				Name:   process.Name,
				IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_GPROCESS}],
			}
		}
	}
	return keyToItem, true
}

func (p *ChGProcess) generateKey(dbItem mysql.ChGProcess) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChGProcess) generateUpdateInfo(oldItem, newItem mysql.ChGProcess) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID {
		updateInfo["icon_id"] = newItem.IconID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
