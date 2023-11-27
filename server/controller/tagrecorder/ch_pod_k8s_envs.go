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

type ChPodK8sEnvs struct {
	UpdaterComponent[mysql.ChPodK8sEnvs, K8sEnvsKey]
}

func NewChPodK8sEnvs() *ChPodK8sEnvs {
	updater := &ChPodK8sEnvs{
		newUpdaterComponent[mysql.ChPodK8sEnvs, K8sEnvsKey](
			RESOURCE_TYPE_CH_K8S_ENVS,
		),
	}
	updater.updaterDG = updater
	return updater
}

func (k *ChPodK8sEnvs) generateNewData() (map[K8sEnvsKey]mysql.ChPodK8sEnvs, bool) {
	var pods []mysql.Pod
	err := mysql.Db.Unscoped().Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[K8sEnvsKey]mysql.ChPodK8sEnvs)
	for _, pod := range pods {
		envsMap := map[string]string{}
		envs := strings.Split(pod.ENV, ", ")
		for _, singleEnv := range envs {
			envInfo := strings.Split(singleEnv, ":")
			if len(envInfo) == 2 {
				envsMap[envInfo[0]] = envInfo[1]
			}
		}
		if len(envsMap) > 0 {
			envStr, err := json.Marshal(envsMap)
			if err != nil {
				log.Error(err)
				return nil, false
			}
			key := K8sEnvsKey{
				ID: pod.ID,
			}
			keyToItem[key] = mysql.ChPodK8sEnvs{
				ID:      pod.ID,
				Envs:    string(envStr),
				L3EPCID: pod.VPCID,
				PodNsID: pod.PodNamespaceID,
			}
		}
	}
	return keyToItem, true
}

func (k *ChPodK8sEnvs) generateKey(dbItem mysql.ChPodK8sEnvs) K8sEnvsKey {
	return K8sEnvsKey{ID: dbItem.ID}
}

func (k *ChPodK8sEnvs) generateUpdateInfo(oldItem, newItem mysql.ChPodK8sEnvs) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Envs != newItem.Envs {
		updateInfo["envs"] = newItem.Envs
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
