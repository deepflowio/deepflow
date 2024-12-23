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

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/tagrecorder"
)

type ChPodK8sAnnotation struct {
	UpdaterBase[metadbmodel.ChPodK8sAnnotation, K8sAnnotationKey]
}

func NewChPodK8sAnnotation() *ChPodK8sAnnotation {
	updater := &ChPodK8sAnnotation{
		UpdaterBase[metadbmodel.ChPodK8sAnnotation, K8sAnnotationKey]{
			resourceTypeName: RESOURCE_TYPE_CH_K8S_ANNOTATION,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (k *ChPodK8sAnnotation) generateNewData() (map[K8sAnnotationKey]metadbmodel.ChPodK8sAnnotation, bool) {
	var pods []metadbmodel.Pod

	err := k.db.Unscoped().Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err), k.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[K8sAnnotationKey]metadbmodel.ChPodK8sAnnotation)
	for _, pod := range pods {
		teamID, err := tagrecorder.GetTeamID(pod.Domain, pod.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", k.resourceTypeName, err.Error(), pod, k.db.LogPrefixORGID)
		}

		annotations := strings.Split(pod.Annotation, ", ")
		for _, singleAnnotation := range annotations {
			annotationInfo := strings.SplitN(singleAnnotation, ":", 2)
			if len(annotationInfo) == 2 {
				key := K8sAnnotationKey{
					ID:  pod.ID,
					Key: annotationInfo[0],
				}
				keyToItem[key] = metadbmodel.ChPodK8sAnnotation{
					ID:          pod.ID,
					Key:         annotationInfo[0],
					Value:       annotationInfo[1],
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

func (k *ChPodK8sAnnotation) generateKey(dbItem metadbmodel.ChPodK8sAnnotation) K8sAnnotationKey {
	return K8sAnnotationKey{ID: dbItem.ID, Key: dbItem.Key}
}

func (k *ChPodK8sAnnotation) generateUpdateInfo(oldItem, newItem metadbmodel.ChPodK8sAnnotation) (map[string]interface{}, bool) {
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
