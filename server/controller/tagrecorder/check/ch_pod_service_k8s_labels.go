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
	"encoding/json"
	"strings"

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChPodServiceK8sLabels struct {
	UpdaterBase[metadbmodel.ChPodServiceK8sLabels, K8sLabelsKey]
}

func NewChPodServiceK8sLabels() *ChPodServiceK8sLabels {
	updater := &ChPodServiceK8sLabels{
		UpdaterBase[metadbmodel.ChPodServiceK8sLabels, K8sLabelsKey]{
			resourceTypeName: RESOURCE_TYPE_CH_K8S_LABELS,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (k *ChPodServiceK8sLabels) generateNewData() (map[K8sLabelsKey]metadbmodel.ChPodServiceK8sLabels, bool) {
	var podServices []metadbmodel.PodService
	err := k.db.Unscoped().Find(&podServices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err), k.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[K8sLabelsKey]metadbmodel.ChPodServiceK8sLabels)
	for _, podService := range podServices {
		teamID, err := tagrecorder.GetTeamID(podService.Domain, podService.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", k.resourceTypeName, err.Error(), podService, k.db.LogPrefixORGID)
		}

		labelsMap := map[string]string{}
		splitLabel := strings.Split(podService.Label, ", ")
		for _, singleLabel := range splitLabel {
			splitSingleLabel := strings.SplitN(singleLabel, ":", 2)
			if len(splitSingleLabel) == 2 {
				labelsMap[splitSingleLabel[0]] = splitSingleLabel[1]
			}
		}
		if len(labelsMap) > 0 {
			labelsStr, err := json.Marshal(labelsMap)
			if err != nil {
				log.Error(err, k.db.LogPrefixORGID)
				return nil, false
			}
			key := K8sLabelsKey{
				ID: podService.ID,
			}
			keyToItem[key] = metadbmodel.ChPodServiceK8sLabels{
				ID:          podService.ID,
				Labels:      string(labelsStr),
				L3EPCID:     podService.VPCID,
				PodNsID:     podService.PodNamespaceID,
				TeamID:      teamID,
				DomainID:    tagrecorder.DomainToDomainID[podService.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[podService.SubDomain],
			}
		}
	}
	return keyToItem, true
}

func (k *ChPodServiceK8sLabels) generateKey(dbItem metadbmodel.ChPodServiceK8sLabels) K8sLabelsKey {
	return K8sLabelsKey{ID: dbItem.ID}
}

func (k *ChPodServiceK8sLabels) generateUpdateInfo(oldItem, newItem metadbmodel.ChPodServiceK8sLabels) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Labels != newItem.Labels {
		updateInfo["labels"] = newItem.Labels
	}
	if oldItem.L3EPCID != newItem.L3EPCID {
		updateInfo["l3_epc_id"] = newItem.L3EPCID
	}
	if oldItem.PodNsID != newItem.PodNsID {
		updateInfo["pod_ns_id"] = newItem.PodNsID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
