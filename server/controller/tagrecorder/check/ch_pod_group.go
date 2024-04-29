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
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
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
	err := p.db.Unscoped().Find(&podGroups).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPodGroup)
	for _, podGroup := range podGroups {
		if podGroup.DeletedAt.Valid {
			keyToItem[IDKey{ID: podGroup.ID}] = mysql.ChPodGroup{
				ID:           podGroup.ID,
				Name:         podGroup.Name + " (deleted)",
				PodGroupType: RESOURCE_POD_GROUP_TYPE_MAP[podGroup.Type],
				IconID:       p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_GROUP}],
				PodClusterID: podGroup.PodClusterID,
				PodNsID:      podGroup.PodNamespaceID,
				TeamID:       tagrecorder.DomainToTeamID[podGroup.Domain],
				DomainID:     tagrecorder.DomainToDomainID[podGroup.Domain],
			}
		} else {
			keyToItem[IDKey{ID: podGroup.ID}] = mysql.ChPodGroup{
				ID:           podGroup.ID,
				Name:         podGroup.Name,
				PodGroupType: RESOURCE_POD_GROUP_TYPE_MAP[podGroup.Type],
				IconID:       p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_GROUP}],
				PodClusterID: podGroup.PodClusterID,
				PodNsID:      podGroup.PodNamespaceID,
				TeamID:       tagrecorder.DomainToTeamID[podGroup.Domain],
				DomainID:     tagrecorder.DomainToDomainID[podGroup.Domain],
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
	if oldItem.PodGroupType != newItem.PodGroupType {
		updateInfo["pod_group_type"] = newItem.PodGroupType
	}
	if oldItem.IconID != newItem.IconID && newItem.IconID != 0 {
		updateInfo["icon_id"] = newItem.IconID
	}
	if oldItem.PodClusterID != newItem.PodClusterID {
		updateInfo["pod_cluster_id"] = newItem.PodClusterID
	}
	if oldItem.PodClusterID != newItem.PodClusterID {
		updateInfo["pod_ns_id"] = newItem.PodNsID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
