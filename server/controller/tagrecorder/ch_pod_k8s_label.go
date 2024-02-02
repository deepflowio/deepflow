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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChPodK8sLabel struct {
	UpdaterComponent[mysql.ChPodK8sLabel, K8sLabelKey]
}

func NewChPodK8sLabel() *ChPodK8sLabel {
	updater := &ChPodK8sLabel{
		newUpdaterComponent[mysql.ChPodK8sLabel, K8sLabelKey](
			RESOURCE_TYPE_CH_K8S_LABEL,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (k *ChPodK8sLabel) generateNewData() (map[K8sLabelKey]mysql.ChPodK8sLabel, bool) {
	var pods []mysql.Pod
	var podGroups []mysql.PodGroup
	var podClusters []mysql.PodCluster
	err := mysql.Db.Unscoped().Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Find(&podGroups).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Unscoped().Find(&podClusters).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err))
		return nil, false
	}

	podClusterIDToVPCID := make(map[int]int)
	for _, podCluster := range podClusters {
		podClusterIDToVPCID[podCluster.ID] = podCluster.VPCID
	}
	keyToItem := make(map[K8sLabelKey]mysql.ChPodK8sLabel)
	for _, pod := range pods {
		splitLabel := strings.Split(pod.Label, ", ")
		for _, singleLabel := range splitLabel {
			splitSingleLabel := strings.Split(singleLabel, ":")
			if len(splitSingleLabel) == 2 {
				key := K8sLabelKey{
					ID:  pod.ID,
					Key: splitSingleLabel[0],
				}
				keyToItem[key] = mysql.ChPodK8sLabel{
					ID:      pod.ID,
					Key:     splitSingleLabel[0],
					Value:   splitSingleLabel[1],
					L3EPCID: pod.VPCID,
					PodNsID: pod.PodNamespaceID,
				}
			}
		}
	}
	return keyToItem, true
}

func (k *ChPodK8sLabel) generateKey(dbItem mysql.ChPodK8sLabel) K8sLabelKey {
	return K8sLabelKey{ID: dbItem.ID, Key: dbItem.Key}
}

func (k *ChPodK8sLabel) generateUpdateInfo(oldItem, newItem mysql.ChPodK8sLabel) (map[string]interface{}, bool) {
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
