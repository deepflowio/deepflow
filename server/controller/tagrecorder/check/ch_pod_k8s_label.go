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
	"strings"

	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChPodK8sLabel struct {
	UpdaterBase[mysqlmodel.ChPodK8sLabel, K8sLabelKey]
}

func NewChPodK8sLabel() *ChPodK8sLabel {
	updater := &ChPodK8sLabel{
		UpdaterBase[mysqlmodel.ChPodK8sLabel, K8sLabelKey]{
			resourceTypeName: RESOURCE_TYPE_CH_K8S_LABEL,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (k *ChPodK8sLabel) generateNewData() (map[K8sLabelKey]mysqlmodel.ChPodK8sLabel, bool) {
	var pods []mysqlmodel.Pod
	var podGroups []mysqlmodel.PodGroup
	var podClusters []mysqlmodel.PodCluster
	err := k.db.Unscoped().Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err), k.db.LogPrefixORGID)
		return nil, false
	}
	err = k.db.Unscoped().Find(&podGroups).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err), k.db.LogPrefixORGID)
		return nil, false
	}
	err = k.db.Unscoped().Find(&podClusters).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err), k.db.LogPrefixORGID)
		return nil, false
	}

	podClusterIDToVPCID := make(map[int]int)
	for _, podCluster := range podClusters {
		podClusterIDToVPCID[podCluster.ID] = podCluster.VPCID
	}
	keyToItem := make(map[K8sLabelKey]mysqlmodel.ChPodK8sLabel)
	for _, pod := range pods {
		teamID, err := tagrecorder.GetTeamID(pod.Domain, pod.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", k.resourceTypeName, err.Error(), pod, k.db.LogPrefixORGID)
		}

		splitLabel := strings.Split(pod.Label, ", ")
		for _, singleLabel := range splitLabel {
			splitSingleLabel := strings.SplitN(singleLabel, ":", 2)
			if len(splitSingleLabel) == 2 {
				key := K8sLabelKey{
					ID:  pod.ID,
					Key: splitSingleLabel[0],
				}
				keyToItem[key] = mysqlmodel.ChPodK8sLabel{
					ID:          pod.ID,
					Key:         splitSingleLabel[0],
					Value:       splitSingleLabel[1],
					L3EPCID:     pod.VPCID,
					PodNsID:     pod.PodNamespaceID,
					TeamID:      teamID,
					DomainID:    tagrecorder.DomainToDomainID[pod.Domain],
					SubDomainID: tagrecorder.SubDomainToSubDomainID[pod.SubDomain],
				}
			}
		}
	}
	return keyToItem, true
}

func (k *ChPodK8sLabel) generateKey(dbItem mysqlmodel.ChPodK8sLabel) K8sLabelKey {
	return K8sLabelKey{ID: dbItem.ID, Key: dbItem.Key}
}

func (k *ChPodK8sLabel) generateUpdateInfo(oldItem, newItem mysqlmodel.ChPodK8sLabel) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Value != newItem.Value {
		updateInfo["value"] = newItem.Value
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
