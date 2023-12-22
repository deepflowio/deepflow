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

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChPodK8sLabels struct {
	UpdaterBase[mysql.ChPodK8sLabels, K8sLabelsKey]
}

func NewChPodK8sLabels() *ChPodK8sLabels {
	updater := &ChPodK8sLabels{
		UpdaterBase[mysql.ChPodK8sLabels, K8sLabelsKey]{
			resourceTypeName: RESOURCE_TYPE_CH_K8S_LABELS,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (k *ChPodK8sLabels) getNewData() ([]mysql.ChPodK8sLabels, bool) {
	var pods []mysql.Pod
	err := mysql.Db.Unscoped().Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err))
		return nil, false
	}

	items := make([]mysql.ChPodK8sLabels, len(pods))
	i := 0
	for _, pod := range pods {
		labelsMap := map[string]string{}
		splitLabel := strings.Split(pod.Label, ", ")
		for _, singleLabel := range splitLabel {
			splitSingleLabel := strings.Split(singleLabel, ":")
			if len(splitSingleLabel) == 2 {
				labelsMap[splitSingleLabel[0]] = splitSingleLabel[1]
			}
		}
		if len(labelsMap) > 0 {
			labelsStr, err := json.Marshal(labelsMap)
			if err != nil {
				log.Error(err)
				return nil, false
			}
			items[i] = mysql.ChPodK8sLabels{
				ID:      pod.ID,
				Labels:  string(labelsStr),
				L3EPCID: pod.VPCID,
				PodNsID: pod.PodNamespaceID,
			}
			i++
		}
	}
	return items, true
}

func (k *ChPodK8sLabels) generateNewData() (map[K8sLabelsKey]mysql.ChPodK8sLabels, bool) {
	items, ok := k.getNewData()
	if !ok {
		return nil, false
	}

	keyToItem := make(map[K8sLabelsKey]mysql.ChPodK8sLabels)
	for _, item := range items {
		keyToItem[K8sLabelsKey{ID: item.ID}] = item
	}
	return keyToItem, true
}

func (k *ChPodK8sLabels) generateKey(dbItem mysql.ChPodK8sLabels) K8sLabelsKey {
	return K8sLabelsKey{ID: dbItem.ID}
}

func (k *ChPodK8sLabels) generateUpdateInfo(oldItem, newItem mysql.ChPodK8sLabels) (map[string]interface{}, bool) {
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
