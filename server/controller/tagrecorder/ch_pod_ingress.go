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

type ChPodIngress struct {
	UpdaterBase[mysql.ChPodIngress, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodIngress(resourceTypeToIconID map[IconKey]int) *ChPodIngress {
	updater := &ChPodIngress{
		UpdaterBase[mysql.ChPodIngress, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_INGRESS,
		},
		resourceTypeToIconID,
	}

	updater.dataGenerator = updater
	return updater
}

func (p *ChPodIngress) getNewData() ([]mysql.ChPodIngress, bool) {
	var podIngresses []mysql.PodIngress
	err := mysql.Db.Unscoped().Find(&podIngresses).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}
	items := make([]mysql.ChPodIngress, len(podIngresses))
	for i, podIngress := range podIngresses {
		items[i] = mysql.ChPodIngress{
			ID:   podIngress.ID,
			Name: podIngress.Name,
		}
		if podIngress.DeletedAt.Valid {
			items[i].Name = podIngress.Name + " (deleted)"
		}
	}
	return items, true
}

func (p *ChPodIngress) generateNewData() (map[IDKey]mysql.ChPodIngress, bool) {
	items, ok := p.getNewData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPodIngress)
	for _, item := range items {
		keyToItem[IDKey{ID: item.ID}] = item
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
