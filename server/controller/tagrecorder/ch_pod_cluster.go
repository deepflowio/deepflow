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

type ChPodCluster struct {
	UpdaterComponent[mysql.ChPodCluster, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodCluster(resourceTypeToIconID map[IconKey]int) *ChPodCluster {
	updater := &ChPodCluster{
		newUpdaterComponent[mysql.ChPodCluster, IDKey](
			RESOURCE_TYPE_CH_POD,
		),
		resourceTypeToIconID,
	}
	updater.updaterDG = updater
	return updater
}

func (p *ChPodCluster) generateNewData() (map[IDKey]mysql.ChPodCluster, bool) {
	var podClusters []mysql.PodCluster
	err := mysql.Db.Unscoped().Find(&podClusters).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPodCluster)
	for _, podCluster := range podClusters {
		if podCluster.DeletedAt.Valid {
			keyToItem[IDKey{ID: podCluster.ID}] = mysql.ChPodCluster{
				ID:     podCluster.ID,
				Name:   podCluster.Name + " (deleted)",
				IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_CLUSTER}],
			}
		} else {
			keyToItem[IDKey{ID: podCluster.ID}] = mysql.ChPodCluster{
				ID:     podCluster.ID,
				Name:   podCluster.Name,
				IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_CLUSTER}],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodCluster) generateKey(dbItem mysql.ChPodCluster) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodCluster) generateUpdateInfo(oldItem, newItem mysql.ChPodCluster) (map[string]interface{}, bool) {
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
