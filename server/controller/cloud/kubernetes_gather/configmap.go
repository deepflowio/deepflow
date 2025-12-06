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

package kubernetes_gather

import (
	"encoding/json"
	"time"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (k *KubernetesGather) getConfigMaps() (configMaps []model.ConfigMap, err error) {
	log.Debug("get configmaps starting", logger.NewORGPrefix(k.orgID))
	for _, c := range k.k8sInfo["*v1.ConfigMap"] {
		cRaw := json.RawMessage(c)
		cData, cErr := rawMessageToMap(cRaw)
		if cErr != nil {
			err = cErr
			log.Errorf("configmap initialization json error: (%s)", cErr.Error(), logger.NewORGPrefix(k.orgID))
			return
		}
		metaData, ok := getJSONMap(cData, "metadata")
		if !ok {
			log.Info("configmap metadata not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		uID := getJSONString(metaData, "uid")
		if uID == "" {
			log.Info("configmap uid not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		name := getJSONString(metaData, "name")
		if name == "" {
			log.Infof("configmap (%s) name not found", uID, logger.NewORGPrefix(k.orgID))
			continue
		}
		uLcuuid := common.IDGenerateUUID(k.orgID, uID)
		namespace := getJSONString(metaData, "namespace")
		namespaceLcuuid, ok := k.namespaceToLcuuid[namespace]
		if !ok {
			log.Infof("configmap (%s) namespace not found", name, logger.NewORGPrefix(k.orgID))
			continue
		}
		var created time.Time
		cTime := getJSONString(metaData, "creationTimestamp")
		if cTime != "" {
			localTime, err := time.Parse(time.RFC3339, cTime)
			if err == nil {
				created = localTime.Local()
			}
		}
		dataMap, _ := getJSONMap(cData, "data")
		if dataMap == nil {
			dataMap = map[string]interface{}{}
		}
		dataStr := k.simpleJsonMarshal(dataMap)
		configMaps = append(configMaps, model.ConfigMap{
			Data:               dataStr,
			DataHash:           cloudcommon.GenerateMD5Sum(dataStr),
			Lcuuid:             uLcuuid,
			Name:               name,
			PodNamespaceLcuuid: namespaceLcuuid,
			CreatedAt:          created,
			VPCLcuuid:          k.VPCUUID,
			AZLcuuid:           k.azLcuuid,
			RegionLcuuid:       k.RegionUUID,
			PodClusterLcuuid:   k.podClusterLcuuid,
		})
		k.configMapToLcuuid[[2]string{namespace, name}] = uLcuuid
	}
	log.Debug("get configmaps complete", logger.NewORGPrefix(k.orgID))
	return
}
