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
	"sort"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChPodServiceK8sLabel struct {
	UpdaterBase[mysql.ChPodServiceK8sLabel, K8sLabelKey]
}

func NewChPodServiceK8sLabel() *ChPodServiceK8sLabel {
	updater := &ChPodServiceK8sLabel{
		UpdaterBase[mysql.ChPodServiceK8sLabel, K8sLabelKey]{
			resourceTypeName: RESOURCE_TYPE_CH_K8S_LABEL,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (k *ChPodServiceK8sLabel) getNewData() ([]mysql.ChPodServiceK8sLabel, bool) {
	keyToItem, ok := k.generateNewData()
	if !ok {
		return nil, false
	}

	items := make([]mysql.ChPodServiceK8sLabel, len(keyToItem))
	i := 0
	for _, data := range keyToItem {
		items[i] = data
		i++
	}
	sort.SliceIsSorted(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})
	sort.SliceIsSorted(items, func(i, j int) bool {
		return items[i].Key < items[j].Key
	})
	return items, true
}

func (k *ChPodServiceK8sLabel) generateNewData() (map[K8sLabelKey]mysql.ChPodServiceK8sLabel, bool) {
	var podServices []mysql.PodService
	var podGroups []mysql.PodGroup
	var podClusters []mysql.PodCluster
	err := mysql.Db.Unscoped().Find(&podServices).Error
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
	keyToItem := make(map[K8sLabelKey]mysql.ChPodServiceK8sLabel)
	for _, podService := range podServices {
		splitLabel := strings.Split(podService.Label, ", ")
		for _, singleLabel := range splitLabel {
			splitSingleLabel := strings.Split(singleLabel, ":")
			if len(splitSingleLabel) == 2 {
				key := K8sLabelKey{
					ID:  podService.ID,
					Key: splitSingleLabel[0],
				}
				keyToItem[key] = mysql.ChPodServiceK8sLabel{
					ID:      podService.ID,
					Key:     splitSingleLabel[0],
					Value:   splitSingleLabel[1],
					L3EPCID: podService.VPCID,
					PodNsID: podService.PodNamespaceID,
				}
			}
		}
	}
	return keyToItem, true
}

func (k *ChPodServiceK8sLabel) generateKey(dbItem mysql.ChPodServiceK8sLabel) K8sLabelKey {
	return K8sLabelKey{ID: dbItem.ID, Key: dbItem.Key}
}

func (k *ChPodServiceK8sLabel) generateUpdateInfo(oldItem, newItem mysql.ChPodServiceK8sLabel) (map[string]interface{}, bool) {
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
