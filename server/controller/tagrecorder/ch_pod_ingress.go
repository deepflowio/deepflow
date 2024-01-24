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

type ChPodIngress struct {
	UpdaterComponent[mysql.ChPodIngress, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodIngress(resourceTypeToIconID map[IconKey]int) *ChPodIngress {
	updater := &ChPodIngress{
		newUpdaterComponent[mysql.ChPodIngress, IDKey](
			RESOURCE_TYPE_CH_POD_INGRESS,
		),
		resourceTypeToIconID,
	}

	updater.updaterDG = updater
	return updater
}

func (p *ChPodIngress) generateNewData() (map[IDKey]mysql.ChPodIngress, bool) {
	var podIngresses []mysql.PodIngress
	err := mysql.Db.Unscoped().Find(&podIngresses).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}
	keyToItem := make(map[IDKey]mysql.ChPodIngress)
	for _, podIngress := range podIngresses {
		if podIngress.DeletedAt.Valid {
			keyToItem[IDKey{ID: podIngress.ID}] = mysql.ChPodIngress{
				ID:   podIngress.ID,
				Name: podIngress.Name + " (deleted)",
			}
		} else {
			keyToItem[IDKey{ID: podIngress.ID}] = mysql.ChPodIngress{
				ID:   podIngress.ID,
				Name: podIngress.Name,
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodIngress) generateKey(dbItem mysql.ChPodIngress) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodIngress) generateUpdateInfo(oldItem, newItem mysql.ChPodIngress) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
