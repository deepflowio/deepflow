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

type ChPodServiceK8sAnnotation struct {
	UpdaterBase[metadbmodel.ChPodServiceK8sAnnotation, K8sAnnotationKey]
}

func NewChPodServiceK8sAnnotation() *ChPodServiceK8sAnnotation {
	updater := &ChPodServiceK8sAnnotation{
		UpdaterBase[metadbmodel.ChPodServiceK8sAnnotation, K8sAnnotationKey]{
			resourceTypeName: RESOURCE_TYPE_CH_K8S_ANNOTATION,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (k *ChPodServiceK8sAnnotation) generateNewData() (map[K8sAnnotationKey]metadbmodel.ChPodServiceK8sAnnotation, bool) {
	var podServices []metadbmodel.PodService

	err := k.db.Unscoped().Find(&podServices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err), k.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[K8sAnnotationKey]metadbmodel.ChPodServiceK8sAnnotation)
	for _, podService := range podServices {
		teamID, err := tagrecorder.GetTeamID(podService.Domain, podService.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", k.resourceTypeName, err.Error(), podService, k.db.LogPrefixORGID)
		}

		annotations := strings.Split(podService.Annotation, ", ")
		for _, singleAnnotation := range annotations {
			annotationInfo := strings.SplitN(singleAnnotation, ":", 2)
			if len(annotationInfo) == 2 {
				key := K8sAnnotationKey{
					ID:  podService.ID,
					Key: annotationInfo[0],
				}
				keyToItem[key] = metadbmodel.ChPodServiceK8sAnnotation{
					ID:          podService.ID,
					Key:         annotationInfo[0],
					Value:       annotationInfo[1],
					L3EPCID:     podService.VPCID,
					PodNsID:     podService.PodNamespaceID,
					TeamID:      teamID,
					DomainID:    tagrecorder.DomainToDomainID[podService.Domain],
					SubDomainID: tagrecorder.SubDomainToSubDomainID[podService.SubDomain],
				}
			}
		}
	}
	return keyToItem, true
}

func (k *ChPodServiceK8sAnnotation) generateKey(dbItem metadbmodel.ChPodServiceK8sAnnotation) K8sAnnotationKey {
	return K8sAnnotationKey{ID: dbItem.ID, Key: dbItem.Key}
}

func (k *ChPodServiceK8sAnnotation) generateUpdateInfo(oldItem, newItem metadbmodel.ChPodServiceK8sAnnotation) (map[string]interface{}, bool) {
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
