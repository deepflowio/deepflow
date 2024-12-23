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

type ChPodIngress struct {
	UpdaterBase[metadbmodel.ChPodIngress, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodIngress(resourceTypeToIconID map[IconKey]int) *ChPodIngress {
	updater := &ChPodIngress{
		UpdaterBase[metadbmodel.ChPodIngress, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_INGRESS,
		},
		resourceTypeToIconID,
	}

	updater.dataGenerator = updater
	return updater
}

func (p *ChPodIngress) generateNewData() (map[IDKey]metadbmodel.ChPodIngress, bool) {
	var podIngresses []metadbmodel.PodIngress
	err := p.db.Unscoped().Find(&podIngresses).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err), p.db.LogPrefixORGID)
		return nil, false
	}
	keyToItem := make(map[IDKey]metadbmodel.ChPodIngress)
	for _, podIngress := range podIngresses {
		teamID, err := tagrecorder.GetTeamID(podIngress.Domain, podIngress.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", p.resourceTypeName, err.Error(), podIngress, p.db.LogPrefixORGID)
		}

		if podIngress.DeletedAt.Valid {
			keyToItem[IDKey{ID: podIngress.ID}] = metadbmodel.ChPodIngress{
				ID:           podIngress.ID,
				PodClusterID: podIngress.PodClusterID,
				PodNsID:      podIngress.PodNamespaceID,
				Name:         podIngress.Name + " (deleted)",
				TeamID:       teamID,
				DomainID:     tagrecorder.DomainToDomainID[podIngress.Domain],
				SubDomainID:  tagrecorder.SubDomainToSubDomainID[podIngress.SubDomain],
			}
		} else {
			keyToItem[IDKey{ID: podIngress.ID}] = metadbmodel.ChPodIngress{
				ID:           podIngress.ID,
				PodClusterID: podIngress.PodClusterID,
				PodNsID:      podIngress.PodNamespaceID,
				Name:         podIngress.Name,
				TeamID:       teamID,
				DomainID:     tagrecorder.DomainToDomainID[podIngress.Domain],
				SubDomainID:  tagrecorder.SubDomainToSubDomainID[podIngress.SubDomain],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodIngress) generateKey(dbItem metadbmodel.ChPodIngress) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodIngress) generateUpdateInfo(oldItem, newItem metadbmodel.ChPodIngress) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
