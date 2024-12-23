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

type ChPodK8sAnnotations struct {
	UpdaterBase[metadbmodel.ChPodK8sAnnotations, K8sAnnotationsKey]
}

func NewChPodK8sAnnotations() *ChPodK8sAnnotations {
	updater := &ChPodK8sAnnotations{
		UpdaterBase[metadbmodel.ChPodK8sAnnotations, K8sAnnotationsKey]{
			resourceTypeName: RESOURCE_TYPE_CH_K8S_ANNOTATIONS,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (k *ChPodK8sAnnotations) generateNewData() (map[K8sAnnotationsKey]metadbmodel.ChPodK8sAnnotations, bool) {
	var pods []metadbmodel.Pod
	err := k.db.Unscoped().Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err), k.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[K8sAnnotationsKey]metadbmodel.ChPodK8sAnnotations)
	for _, pod := range pods {
		teamID, err := tagrecorder.GetTeamID(pod.Domain, pod.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", k.resourceTypeName, err.Error(), pod, k.db.LogPrefixORGID)
		}

		annotationsMap := map[string]string{}
		annotations := strings.Split(pod.Annotation, ", ")
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
				ID: pod.ID,
			}
			keyToItem[key] = metadbmodel.ChPodK8sAnnotations{
				ID:          pod.ID,
				Annotations: string(annotationStr),
				L3EPCID:     pod.VPCID,
				PodNsID:     pod.PodNamespaceID,
				TeamID:      teamID,
				DomainID:    tagrecorder.DomainToDomainID[pod.Domain],
				SubDomainID: tagrecorder.SubDomainToSubDomainID[pod.SubDomain],
			}
		}
	}
	return keyToItem, true
}

func (k *ChPodK8sAnnotations) generateKey(dbItem metadbmodel.ChPodK8sAnnotations) K8sAnnotationsKey {
	return K8sAnnotationsKey{ID: dbItem.ID}
}

func (k *ChPodK8sAnnotations) generateUpdateInfo(oldItem, newItem metadbmodel.ChPodK8sAnnotations) (map[string]interface{}, bool) {
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
