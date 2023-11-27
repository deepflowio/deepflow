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

type ChPodNode struct {
	UpdaterComponent[mysql.ChPodNode, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNode(resourceTypeToIconID map[IconKey]int) *ChPodNode {
	updater := &ChPodNode{
		newUpdaterComponent[mysql.ChPodNode, IDKey](
			RESOURCE_TYPE_CH_POD_NODE,
		),
		resourceTypeToIconID,
	}
	updater.updaterDG = updater
	return updater
}

func (p *ChPodNode) generateNewData() (map[IDKey]mysql.ChPodNode, bool) {
	var podNodes []mysql.PodNode
	err := mysql.Db.Unscoped().Find(&podNodes).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPodNode)
	for _, podNode := range podNodes {
		if podNode.DeletedAt.Valid {
			keyToItem[IDKey{ID: podNode.ID}] = mysql.ChPodNode{
				ID:     podNode.ID,
				Name:   podNode.Name + " (deleted)",
				IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NODE}],
			}
		} else {
			keyToItem[IDKey{ID: podNode.ID}] = mysql.ChPodNode{
				ID:     podNode.ID,
				Name:   podNode.Name,
				IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NODE}],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodNode) generateKey(dbItem mysql.ChPodNode) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodNode) generateUpdateInfo(oldItem, newItem mysql.ChPodNode) (map[string]interface{}, bool) {
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
