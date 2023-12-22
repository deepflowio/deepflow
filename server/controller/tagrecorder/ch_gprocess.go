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
	"github.com/deepflowio/deepflow/server/controller/db/mysql/query"
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

func (p *ChGProcess) getNewData() ([]mysql.ChGProcess, bool) {
	processes, err := query.FindInBatches[mysql.Process](mysql.Db.Unscoped())
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	items := make([]mysql.ChGProcess, len(processes))
	for i, process := range processes {
		items[i] = mysql.ChGProcess{
			ID:     process.ID,
			Name:   process.Name,
			IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_GPROCESS}],
		}
		if process.DeletedAt.Valid {
			items[i].Name = process.Name + " (deleted)"
		}
	}
	return items, true
}

func (p *ChGProcess) generateNewData() (map[IDKey]mysql.ChGProcess, bool) {
	items, ok := p.getNewData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChGProcess, len(items))
	for _, item := range items {
		keyToItem[IDKey{ID: item.ID}] = item
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
