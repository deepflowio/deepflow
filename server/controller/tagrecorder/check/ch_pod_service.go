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

type ChPodService struct {
	UpdaterBase[metadbmodel.ChPodService, IDKey]
}

func NewChPodService() *ChPodService {
	updater := &ChPodService{
		UpdaterBase[metadbmodel.ChPodService, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_SERVICE,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodService) generateNewData() (map[IDKey]metadbmodel.ChPodService, bool) {
	var podServices []metadbmodel.PodService
	err := p.db.Unscoped().Find(&podServices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), p.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[IDKey]metadbmodel.ChPodService)
	for _, podService := range podServices {
		teamID, err := tagrecorder.GetTeamID(podService.Domain, podService.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", p.resourceTypeName, err.Error(), podService, p.db.LogPrefixORGID)
		}

		if podService.DeletedAt.Valid {
			keyToItem[IDKey{ID: podService.ID}] = metadbmodel.ChPodService{
				ID:           podService.ID,
				Name:         podService.Name + " (deleted)",
				PodClusterID: podService.PodClusterID,
				PodNsID:      podService.PodNamespaceID,
				TeamID:       teamID,
				DomainID:     tagrecorder.DomainToDomainID[podService.Domain],
				SubDomainID:  tagrecorder.SubDomainToSubDomainID[podService.SubDomain],
			}
		} else {
			keyToItem[IDKey{ID: podService.ID}] = metadbmodel.ChPodService{
				ID:           podService.ID,
				Name:         podService.Name,
				PodClusterID: podService.PodClusterID,
				PodNsID:      podService.PodNamespaceID,
				TeamID:       teamID,
				DomainID:     tagrecorder.DomainToDomainID[podService.Domain],
				SubDomainID:  tagrecorder.SubDomainToSubDomainID[podService.SubDomain],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodService) generateKey(dbItem metadbmodel.ChPodService) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodService) generateUpdateInfo(oldItem, newItem metadbmodel.ChPodService) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
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
