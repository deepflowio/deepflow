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

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type ChPodServiceK8sAnnotation struct {
	UpdaterBase[mysql.ChPodServiceK8sAnnotation, K8sAnnotationKey]
}

func NewChPodServiceK8sAnnotation() *ChPodServiceK8sAnnotation {
	updater := &ChPodServiceK8sAnnotation{
		UpdaterBase[mysql.ChPodServiceK8sAnnotation, K8sAnnotationKey]{
			resourceTypeName: RESOURCE_TYPE_CH_K8S_ANNOTATION,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (k *ChPodServiceK8sAnnotation) generateNewData() (map[K8sAnnotationKey]mysql.ChPodServiceK8sAnnotation, bool) {
	var podServices []mysql.PodService

	err := mysql.Db.Unscoped().Find(&podServices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[K8sAnnotationKey]mysql.ChPodServiceK8sAnnotation)
	for _, podService := range podServices {
		annotations := strings.Split(podService.Annotation, ", ")
		for _, singleAnnotation := range annotations {
			annotationInfo := strings.Split(singleAnnotation, ":")
			if len(annotationInfo) == 2 {
				key := K8sAnnotationKey{
					ID:  podService.ID,
					Key: annotationInfo[0],
				}
				keyToItem[key] = mysql.ChPodServiceK8sAnnotation{
					ID:      podService.ID,
					Key:     annotationInfo[0],
					Value:   annotationInfo[1],
					L3EPCID: podService.VPCID,
					PodNsID: podService.PodNamespaceID,
				}
			}
		}
	}
	return keyToItem, true
}

func (k *ChPodServiceK8sAnnotation) generateKey(dbItem mysql.ChPodServiceK8sAnnotation) K8sAnnotationKey {
	return K8sAnnotationKey{ID: dbItem.ID, Key: dbItem.Key}
}

func (k *ChPodServiceK8sAnnotation) generateUpdateInfo(oldItem, newItem mysql.ChPodServiceK8sAnnotation) (map[string]interface{}, bool) {
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
