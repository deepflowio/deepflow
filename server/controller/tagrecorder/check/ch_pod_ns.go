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

type ChPodNamespace struct {
	UpdaterBase[metadbmodel.ChPodNamespace, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNamespace(resourceTypeToIconID map[IconKey]int) *ChPodNamespace {
	updater := &ChPodNamespace{
		UpdaterBase[metadbmodel.ChPodNamespace, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_NAMESPACE,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodNamespace) generateNewData() (map[IDKey]metadbmodel.ChPodNamespace, bool) {
	var podNamespaces []metadbmodel.PodNamespace
	err := p.db.Unscoped().Find(&podNamespaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), p.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]metadbmodel.ChPodNamespace)
	for _, podNamespace := range podNamespaces {
		teamID, err := tagrecorder.GetTeamID(podNamespace.Domain, podNamespace.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", p.resourceTypeName, err.Error(), podNamespace, p.db.LogPrefixORGID)
		}

		if podNamespace.DeletedAt.Valid {
			keyToItem[IDKey{ID: podNamespace.ID}] = metadbmodel.ChPodNamespace{
				ID:           podNamespace.ID,
				Name:         podNamespace.Name + " (deleted)",
				IconID:       p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NAMESPACE}],
				PodClusterID: podNamespace.PodClusterID,
				TeamID:       teamID,
				DomainID:     tagrecorder.DomainToDomainID[podNamespace.Domain],
				SubDomainID:  tagrecorder.SubDomainToSubDomainID[podNamespace.SubDomain],
			}
		} else {
			keyToItem[IDKey{ID: podNamespace.ID}] = metadbmodel.ChPodNamespace{
				ID:           podNamespace.ID,
				Name:         podNamespace.Name,
				IconID:       p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NAMESPACE}],
				PodClusterID: podNamespace.PodClusterID,
				TeamID:       teamID,
				DomainID:     tagrecorder.DomainToDomainID[podNamespace.Domain],
				SubDomainID:  tagrecorder.SubDomainToSubDomainID[podNamespace.SubDomain],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodNamespace) generateKey(dbItem metadbmodel.ChPodNamespace) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodNamespace) generateUpdateInfo(oldItem, newItem metadbmodel.ChPodNamespace) (map[string]interface{}, bool) {
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
