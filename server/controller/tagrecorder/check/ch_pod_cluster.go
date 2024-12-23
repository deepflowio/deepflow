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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChPodCluster struct {
	UpdaterBase[metadbmodel.ChPodCluster, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodCluster(resourceTypeToIconID map[IconKey]int) *ChPodCluster {
	updater := &ChPodCluster{
		UpdaterBase[metadbmodel.ChPodCluster, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_CLUSTER,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodCluster) generateNewData() (map[IDKey]metadbmodel.ChPodCluster, bool) {
	var podClusters []metadbmodel.PodCluster
	err := p.db.Unscoped().Find(&podClusters).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), p.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]metadbmodel.ChPodCluster)
	for _, podCluster := range podClusters {
		teamID, err := tagrecorder.GetTeamID(podCluster.Domain, podCluster.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", p.resourceTypeName, err.Error(), podCluster, p.db.LogPrefixORGID)
		}
		if podCluster.DeletedAt.Valid {
			keyToItem[IDKey{ID: podCluster.ID}] = metadbmodel.ChPodCluster{
				ID:          podCluster.ID,
				Name:        podCluster.Name + " (deleted)",
				IconID:      p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_CLUSTER}],
				TeamID:      teamID,
				DomainID:    tagrecorder.DomainToDomainID[podCluster.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podCluster.SubDomain],
			}
		} else {
			keyToItem[IDKey{ID: podCluster.ID}] = metadbmodel.ChPodCluster{
				ID:          podCluster.ID,
				Name:        podCluster.Name,
				IconID:      p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_CLUSTER}],
				TeamID:      teamID,
				DomainID:    tagrecorder.DomainToDomainID[podCluster.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podCluster.SubDomain],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodCluster) generateKey(dbItem metadbmodel.ChPodCluster) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodCluster) generateUpdateInfo(oldItem, newItem metadbmodel.ChPodCluster) (map[string]interface{}, bool) {
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
