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
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChPodNode struct {
	UpdaterBase[mysqlmodel.ChPodNode, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNode(resourceTypeToIconID map[IconKey]int) *ChPodNode {
	updater := &ChPodNode{
		UpdaterBase[mysqlmodel.ChPodNode, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_NODE,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodNode) generateNewData() (map[IDKey]mysqlmodel.ChPodNode, bool) {
	var podNodes []mysqlmodel.PodNode
	err := p.db.Unscoped().Find(&podNodes).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), p.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]mysqlmodel.ChPodNode)
	for _, podNode := range podNodes {
		teamID, err := tagrecorder.GetTeamID(podNode.Domain, podNode.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", p.resourceTypeName, err.Error(), podNode, p.db.LogPrefixORGID)
		}

		if podNode.DeletedAt.Valid {
			keyToItem[IDKey{ID: podNode.ID}] = mysqlmodel.ChPodNode{
				ID:           podNode.ID,
				Name:         podNode.Name + " (deleted)",
				PodClusterID: podNode.PodClusterID,
				IconID:       p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NODE}],
				TeamID:       teamID,
				DomainID:     tagrecorder.DomainToDomainID[podNode.Domain],
				SubDomainID:  tagrecorder.SubDomainToSubDomainID[podNode.SubDomain],
			}
		} else {
			keyToItem[IDKey{ID: podNode.ID}] = mysqlmodel.ChPodNode{
				ID:           podNode.ID,
				Name:         podNode.Name,
				PodClusterID: podNode.PodClusterID,
				IconID:       p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NODE}],
				TeamID:       teamID,
				DomainID:     tagrecorder.DomainToDomainID[podNode.Domain],
				SubDomainID:  tagrecorder.SubDomainToSubDomainID[podNode.SubDomain],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodNode) generateKey(dbItem mysqlmodel.ChPodNode) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodNode) generateUpdateInfo(oldItem, newItem mysqlmodel.ChPodNode) (map[string]interface{}, bool) {
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
