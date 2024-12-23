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

type ChPodK8sEnv struct {
	UpdaterBase[metadbmodel.ChPodK8sEnv, K8sEnvKey]
}

func NewChPodK8sEnv() *ChPodK8sEnv {
	updater := &ChPodK8sEnv{
		UpdaterBase[metadbmodel.ChPodK8sEnv, K8sEnvKey]{
			resourceTypeName: RESOURCE_TYPE_CH_K8S_ENV,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (k *ChPodK8sEnv) generateNewData() (map[K8sEnvKey]metadbmodel.ChPodK8sEnv, bool) {
	var pods []metadbmodel.Pod

	err := k.db.Unscoped().Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err), k.db.LogPrefixORGID)
		return nil, false
	}

	keyToItem := make(map[K8sEnvKey]metadbmodel.ChPodK8sEnv)
	for _, pod := range pods {
		teamID, err := tagrecorder.GetTeamID(pod.Domain, pod.SubDomain)
		if err != nil {
			log.Errorf("resource(%s) %s, resource: %#v", k.resourceTypeName, err.Error(), pod, k.db.LogPrefixORGID)
		}

		envs := strings.Split(pod.ENV, ", ")
		for _, singleEnv := range envs {
			envInfo := strings.SplitN(singleEnv, ":", 2)
			if len(envInfo) == 2 {
				key := K8sEnvKey{
					ID:  pod.ID,
					Key: envInfo[0],
				}
				keyToItem[key] = metadbmodel.ChPodK8sEnv{
					ID:          pod.ID,
					Key:         envInfo[0],
					Value:       envInfo[1],
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

func (k *ChPodK8sEnv) generateKey(dbItem metadbmodel.ChPodK8sEnv) K8sEnvKey {
	return K8sEnvKey{ID: dbItem.ID, Key: dbItem.Key}
}

func (k *ChPodK8sEnv) generateUpdateInfo(oldItem, newItem metadbmodel.ChPodK8sEnv) (map[string]interface{}, bool) {
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
