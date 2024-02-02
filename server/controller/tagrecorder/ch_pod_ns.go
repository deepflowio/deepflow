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

type ChPodNamespace struct {
	UpdaterComponent[mysql.ChPodNamespace, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNamespace(resourceTypeToIconID map[IconKey]int) *ChPodNamespace {
	updater := &ChPodNamespace{
		newUpdaterComponent[mysql.ChPodNamespace, IDKey](
			RESOURCE_TYPE_CH_POD_NAMESPACE,
		),
		resourceTypeToIconID,
	}
	updater.updaterDG = updater
	return updater
}

func (p *ChPodNamespace) generateNewData() (map[IDKey]mysql.ChPodNamespace, bool) {
	var podNamespaces []mysql.PodNamespace
	err := mysql.Db.Unscoped().Find(&podNamespaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPodNamespace)
	for _, podNamespace := range podNamespaces {
		if podNamespace.DeletedAt.Valid {
			keyToItem[IDKey{ID: podNamespace.ID}] = mysql.ChPodNamespace{
				ID:           podNamespace.ID,
				Name:         podNamespace.Name + " (deleted)",
				IconID:       p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NAMESPACE}],
				PodClusterID: podNamespace.PodClusterID,
			}
		} else {
			keyToItem[IDKey{ID: podNamespace.ID}] = mysql.ChPodNamespace{
				ID:           podNamespace.ID,
				Name:         podNamespace.Name,
				IconID:       p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NAMESPACE}],
				PodClusterID: podNamespace.PodClusterID,
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodNamespace) generateKey(dbItem mysql.ChPodNamespace) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodNamespace) generateUpdateInfo(oldItem, newItem mysql.ChPodNamespace) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID && newItem.IconID != 0 {
		updateInfo["icon_id"] = newItem.IconID
	}
	if oldItem.PodClusterID != newItem.PodClusterID {
		updateInfo["pod_cluster_id"] = newItem.PodClusterID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
