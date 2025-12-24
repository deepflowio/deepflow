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
	"sort"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
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
	for _, p := range k.k8sEntries["*v1.Pod"] {
		pData, pErr := simplejson.NewJson(p)
		if pErr != nil {
			err = pErr
			log.Errorf("pod initialization simplejson error: (%s)", pErr.Error(), logger.NewORGPrefix(k.orgID))
			return
		}

		envString := expand.GetPodENV(pData, k.envRegex, k.customTagLenMax)

		metaData, ok := pData.CheckGet("metadata")
		if !ok {
			log.Info("pod metadata not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		uID := metaData.Get("uid").MustString()
		if uID == "" {
			log.Info("pod uid not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		name := metaData.Get("name").MustString()
		if name == "" {
			log.Infof("pod (%s) name not found", uID, logger.NewORGPrefix(k.orgID))
			continue
		}
		namespace := metaData.Get("namespace").MustString()
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
			podGroups := metaData.Get("ownerReferences")
			podGroupUID = podGroups.GetIndex(0).Get("uid").MustString()
			if podGroupUID == "" {
				log.Infof("pod (%s) pod group not found", name, logger.NewORGPrefix(k.orgID))
				continue
			}
			kind = podGroups.GetIndex(0).Get("kind").MustString()
			if _, ok := podTypesMap[kind]; !ok {
				log.Infof("pod group (%s) type (%s) not support", name, kind, logger.NewORGPrefix(k.orgID))
				continue
			}
		}
		hostIP := pData.Get("status").Get("hostIP").MustString()

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
		if generateName, ok := metaData.CheckGet("generateName"); ok {
			serialNumber := strings.TrimLeft(name, generateName.MustString())
			podLcuuid = common.GetUUIDByOrgID(k.orgID, pgLcuuid+serialNumber)
		} else {
			podLcuuid = common.IDGenerateUUID(k.orgID, uID)
		}
		conditions := pData.Get("status").Get("conditions")
		conditionStatus := []string{}
		for i := range conditions.MustArray() {
			cData := conditions.GetIndex(i).MustMap()
			cType, ok := cData["type"].(string)
			if !ok {
				continue
			}
			if cType == "Ready" {
				cStatus, ok := cData["status"].(string)
				if !ok {
					continue
				}
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
		cTime := metaData.Get("creationTimestamp").MustString()
		if cTime != "" {
			localTime, err := time.Parse(time.RFC3339, cTime)
			if err == nil {
				created = localTime.Local()
			}
		}
		labels := metaData.Get("labels").MustMap()
		if exLabels, ok := k.namespaceToExLabels[namespace]; ok {
			for exK, exV := range exLabels {
				labels[exK] = exV
			}
		}

		annotations := metaData.Get("annotations")
		annotationString := expand.GetAnnotation(annotations, k.annotationRegex, k.customTagLenMax)

		containerIDs := []string{}
		containerStatuses := pData.GetPath("status", "containerStatuses")
		for c := range containerStatuses.MustArray() {
			containerID := containerStatuses.GetIndex(c).Get("containerID").MustString()
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
		podIP := pData.Get("status").Get("podIP").MustString()
		podIPs := []string{podIP}
		if podNetworks, ok := pData.Get("status").CheckGet("podNetworks"); ok {
			for i := range podNetworks.MustArray() {
				port := podNetworks.GetIndex(i).MustMap()
				podIPs = append(podIPs, port["ip"].([]string)...)
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
