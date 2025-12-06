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
	"sort"
	"strings"
	"time"

	"github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/expand"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (k *KubernetesGather) getPods() (pods []model.Pod, err error) {
	log.Debug("get pods starting", logger.NewORGPrefix(k.orgID))
	podTypesMap := map[string]bool{
		"CloneSet":              false,
		"DaemonSet":             false,
		"Deployment":            false,
		"InPlaceSet":            false,
		"ReplicaSet":            false,
		"StatefulSet":           false,
		"StatefulSetPlus":       false,
		"OpenGaussCluster":      false,
		"ReplicationController": false,
	}
	for _, p := range k.k8sInfo["*v1.Pod"] {
		pRaw := json.RawMessage(p)
		pData, pErr := rawMessageToMap(pRaw)
		if pErr != nil {
			err = pErr
			log.Errorf("pod initialization json error: (%s)", pErr.Error(), logger.NewORGPrefix(k.orgID))
			return
		}

		envString := expand.GetPodENV(pData, k.envRegex, k.customTagLenMax)

		metaData, ok := getJSONMap(pData, "metadata")
		if !ok {
			log.Info("pod metadata not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		uID := getJSONString(metaData, "uid")
		if uID == "" {
			log.Info("pod uid not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		name := getJSONString(metaData, "name")
		if name == "" {
			log.Infof("pod (%s) name not found", uID, logger.NewORGPrefix(k.orgID))
			continue
		}
		namespace := getJSONString(metaData, "namespace")
		namespaceLcuuid, ok := k.namespaceToLcuuid[namespace]
		if !ok {
			log.Infof("pod (%s) namespace not found", name, logger.NewORGPrefix(k.orgID))
			continue
		}

		var podGroupUID, kind string
		if pgInfo, ok := k.podLcuuidToPGInfo[uID]; ok {
			podGroupUID = pgInfo[0]
			kind = pgInfo[1]
		} else {
			ownerRefs, _ := getJSONArray(metaData, "ownerReferences")
			if len(ownerRefs) == 0 {
				log.Infof("pod (%s) pod group not found", name, logger.NewORGPrefix(k.orgID))
				continue
			}
			if ownerRef, ok := ownerRefs[0].(map[string]interface{}); ok {
				podGroupUID = getJSONString(ownerRef, "uid")
				if podGroupUID == "" {
					log.Infof("pod (%s) pod group not found", name, logger.NewORGPrefix(k.orgID))
					continue
				}
				kind = getJSONString(ownerRef, "kind")
				if _, ok := podTypesMap[kind]; !ok {
					log.Infof("pod group (%s) type (%s) not support", name, kind, logger.NewORGPrefix(k.orgID))
					continue
				}
			} else {
				log.Infof("pod (%s) ownerReferences invalid", name, logger.NewORGPrefix(k.orgID))
				continue
			}
		}
		statusData := getJSONPath(pData, "status")
		hostIP := getJSONString(statusData, "hostIP")

		podRSLcuuid := ""
		podGroupLcuuid := ""
		podLcuuid := ""
		pgLcuuid := common.IDGenerateUUID(k.orgID, podGroupUID)
		if gLcuuid, ok := k.rsLcuuidToPodGroupLcuuid[pgLcuuid]; ok {
			podRSLcuuid = pgLcuuid
			podGroupLcuuid = gLcuuid
		} else {
			if !k.podGroupLcuuids.Contains(pgLcuuid) {
				log.Debugf("pod (%s) pod group not found", name, logger.NewORGPrefix(k.orgID))
				continue
			}
			podGroupLcuuid = pgLcuuid
		}
		generateName := getJSONString(metaData, "generateName")
		if generateName != "" {
			serialNumber := strings.TrimLeft(name, generateName)
			podLcuuid = common.GetUUIDByOrgID(k.orgID, pgLcuuid+serialNumber)
		} else {
			podLcuuid = common.IDGenerateUUID(k.orgID, uID)
		}
		conditions, _ := getJSONArray(statusData, "conditions")
		conditionStatus := []string{}
		for _, conditionInterface := range conditions {
			cData, ok := conditionInterface.(map[string]interface{})
			if !ok {
				continue
			}
			cType := getJSONString(cData, "type")
			if cType == "Ready" {
				cStatus := getJSONString(cData, "status")
				conditionStatus = append(conditionStatus, cStatus)
			}
		}
		status := 0
		if len(conditionStatus) != 0 && conditionStatus[0] == "True" {
			status = common.POD_STATE_RUNNING
		} else {
			status = common.POD_STATE_EXCEPTION
		}
		var created time.Time
		cTime := getJSONString(metaData, "creationTimestamp")
		if cTime != "" {
			localTime, err := time.Parse(time.RFC3339, cTime)
			if err == nil {
				created = localTime.Local()
			}
		}
		labels, _ := getJSONMap(metaData, "labels")
		if labels == nil {
			labels = map[string]interface{}{}
		}
		if exLabels, ok := k.namespaceToExLabels[namespace]; ok {
			for exK, exV := range exLabels {
				labels[exK] = exV
			}
		}

		annotations, _ := getJSONMap(metaData, "annotations")
		annotationString := expand.GetAnnotation(annotations, k.annotationRegex, k.customTagLenMax)

		containerIDs := []string{}
		containerStatuses, _ := getJSONArray(statusData, "containerStatuses")
		for _, containerStatusInterface := range containerStatuses {
			containerStatus, ok := containerStatusInterface.(map[string]interface{})
			if !ok {
				continue
			}
			containerID := getJSONString(containerStatus, "containerID")
			if containerID == "" {
				continue
			}
			cIndex := strings.Index(containerID, "://")
			if cIndex != -1 {
				containerID = containerID[cIndex+3:]
			}
			containerIDs = append(containerIDs, containerID)
		}
		sort.Strings(containerIDs)

		var podServiceLcuuid string
		podServiceLcuuids, ok := k.pgLcuuidToPSLcuuids[podGroupLcuuid]
		if ok && len(podServiceLcuuids) > 0 {
			sort.Strings(podServiceLcuuids)
			podServiceLcuuid = podServiceLcuuids[0]
		}

		pod := model.Pod{
			Lcuuid:              podLcuuid,
			Name:                name,
			State:               status,
			VPCLcuuid:           k.VPCUUID,
			ENV:                 envString,
			Label:               k.GetLabel(labels),
			Annotation:          annotationString,
			ContainerIDs:        strings.Join(containerIDs, ", "),
			PodReplicaSetLcuuid: podRSLcuuid,
			PodNodeLcuuid:       k.nodeIPToLcuuid[hostIP],
			PodGroupLcuuid:      podGroupLcuuid,
			PodServiceLcuuid:    podServiceLcuuid,
			PodNamespaceLcuuid:  namespaceLcuuid,
			CreatedAt:           created,
			AZLcuuid:            k.azLcuuid,
			RegionLcuuid:        k.RegionUUID,
			PodClusterLcuuid:    k.podClusterLcuuid,
		}
		pods = append(pods, pod)
		podIP := getJSONString(statusData, "podIP")
		podIPs := []string{podIP}
		if podNetworks, ok := getJSONArray(statusData, "podNetworks"); ok {
			for _, podNetworkInterface := range podNetworks {
				podNetwork, ok := podNetworkInterface.(map[string]interface{})
				if !ok {
					continue
				}
				if ipValue, exists := podNetwork["ip"]; exists {
					switch v := ipValue.(type) {
					case string:
						if v != "" {
							podIPs = append(podIPs, v)
						}
					case []interface{}:
						for _, ipInterface := range v {
							if ipStr, ok := ipInterface.(string); ok && ipStr != "" {
								podIPs = append(podIPs, ipStr)
							}
						}
					case []string:
						for _, ipStr := range v {
							if ipStr != "" {
								podIPs = append(podIPs, ipStr)
							}
						}
					}
				}
			}
		}
		for _, ip := range podIPs {
			if ip == "" {
				continue
			}
			if _, ok := k.nodeIPToLcuuid[ip]; !ok {
				k.podIPToLcuuid[ip] = podLcuuid
			}
		}
	}
	log.Debug("get pods complete", logger.NewORGPrefix(k.orgID))
	return
}
