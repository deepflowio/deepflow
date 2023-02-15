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

type ChPodGroup struct {
	UpdaterBase[mysql.ChPodGroup, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodGroup(resourceTypeToIconID map[IconKey]int) *ChPodGroup {
	updater := &ChPodGroup{
		UpdaterBase[mysql.ChPodGroup, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_GROUP,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodGroup) generateNewData() (map[IDKey]mysql.ChPodGroup, bool) {
	var podGroups []mysql.PodGroup
	err := mysql.Db.Unscoped().Find(&podGroups).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPodGroup)
	for _, podGroup := range podGroups {
		if podGroup.DeletedAt.Valid {
			keyToItem[IDKey{ID: podGroup.ID}] = mysql.ChPodGroup{
				ID:     podGroup.ID,
				Name:   podGroup.Name + " (deleted)",
				IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_GROUP}],
			}
		} else {
			keyToItem[IDKey{ID: podGroup.ID}] = mysql.ChPodGroup{
				ID:     podGroup.ID,
				Name:   podGroup.Name,
				IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_GROUP}],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodGroup) generateKey(dbItem mysql.ChPodGroup) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodGroup) generateUpdateInfo(oldItem, newItem mysql.ChPodGroup) (map[string]interface{}, bool) {
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
