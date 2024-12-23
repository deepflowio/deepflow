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

type ChPodServiceK8sAnnotations struct {
	UpdaterBase[metadbmodel.ChPodServiceK8sAnnotations, K8sAnnotationsKey]
}

func NewChPodServiceK8sAnnotations() *ChPodServiceK8sAnnotations {
	updater := &ChPodServiceK8sAnnotations{
		UpdaterBase[metadbmodel.ChPodServiceK8sAnnotations, K8sAnnotationsKey]{
			resourceTypeName: RESOURCE_TYPE_CH_K8S_ANNOTATIONS,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (k *ChPodServiceK8sAnnotations) generateNewData() (map[K8sAnnotationsKey]metadbmodel.ChPodServiceK8sAnnotations, bool) {
	var podServices []metadbmodel.PodService
	err := k.db.Unscoped().Find(&podServices).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err), k.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[K8sAnnotationsKey]metadbmodel.ChPodServiceK8sAnnotations)
	for _, podService := range podServices {
		teamID, err := tagrecorder.GetTeamID(podService.Domain, podService.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", k.resourceTypeName, err.Error(), podService, k.db.LogPrefixORGID)
		}

		annotationsMap := map[string]string{}
		annotations := strings.Split(podService.Annotation, ", ")
		for _, singleAnnotation := range annotations {
			annotationInfo := strings.SplitN(singleAnnotation, ":", 2)
			if len(annotationInfo) == 2 {
				annotationsMap[annotationInfo[0]] = annotationInfo[1]
			}
		}
		if len(annotationsMap) > 0 {
			annotationStr, err := json.Marshal(annotationsMap)
			if err != nil {
				log.Error(err, k.db.LogPrefixORGID)
				return nil, false
			}
			key := K8sAnnotationsKey{
				ID: podService.ID,
			}
			keyToItem[key] = metadbmodel.ChPodServiceK8sAnnotations{
				ID:          podService.ID,
				Annotations: string(annotationStr),
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

func (k *ChPodServiceK8sAnnotations) generateKey(dbItem metadbmodel.ChPodServiceK8sAnnotations) K8sAnnotationsKey {
	return K8sAnnotationsKey{ID: dbItem.ID}
}

func (k *ChPodServiceK8sAnnotations) generateUpdateInfo(oldItem, newItem metadbmodel.ChPodServiceK8sAnnotations) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Annotations != newItem.Annotations {
		updateInfo["annotations"] = newItem.Annotations
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
