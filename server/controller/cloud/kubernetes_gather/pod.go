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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/expand"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (k *KubernetesGather) getPods() (pods []model.Pod, err error) {
	log.Debug("get pods starting")
	podTypesMap := map[string]bool{
		"CloneSet":              false,
		"DaemonSet":             false,
		"Deployment":            false,
		"InPlaceSet":            false,
		"ReplicaSet":            false,
		"StatefulSet":           false,
		"ReplicationController": false,
	}
	for _, p := range k.k8sInfo["*v1.Pod"] {
		pData, pErr := simplejson.NewJson([]byte(p))
		if pErr != nil {
			err = pErr
			log.Errorf("pod initialization simplejson error: (%s)", pErr.Error())
			return
		}

		envString := expand.GetPodENV(pData, k.envRegex, k.customTagLenMax)

		metaData, ok := pData.CheckGet("metadata")
		if !ok {
			log.Info("pod metadata not found")
			continue
		}
		uID := metaData.Get("uid").MustString()
		if uID == "" {
			log.Info("pod uid not found")
			continue
		}
		name := metaData.Get("name").MustString()
		if name == "" {
			log.Infof("pod (%s) name not found", uID)
			continue
		}
		namespace := metaData.Get("namespace").MustString()
		namespaceLcuuid, ok := k.namespaceToLcuuid[namespace]
		if !ok {
			log.Infof("pod (%s) namespace not found", name)
			continue
		}

		podGroups := metaData.Get("ownerReferences")
		if len(podGroups.MustArray()) == 0 {
			providerType := metaData.Get("labels").Get("virtual-kubelet.io/provider-cluster-type").MustString()
			if providerType != "serverless" && providerType != "proprietary" {
				log.Debugf("pod (%s) type (%s) ownerReferences not found or sci cluster type not support", name, providerType)
				continue
			}
			abstractPGType := metaData.Get("labels").Get("virtual-kubelet.io/provider-workload-type").MustString()
			if abstractPGType == "" {
				if _, ok := metaData.Get("labels").CheckGet("statefulset.kubernetes.io/pod-name"); ok {
					abstractPGType = "StatefulSet"
				} else {
					abstractPGType = "Deployment"
				}
			}
			resourceName := metaData.Get("labels").Get("virtual-kubelet.io/provider-resource-name").MustString()
			if resourceName == "" {
				log.Debugf("sci pod (%s) not found provider resource name", name)
				continue
			}
			abstractPGName := resourceName
			targetIndex := strings.LastIndex(resourceName, "-")
			if targetIndex != -1 {
				abstractPGName = resourceName[:targetIndex]
			}
			uid := common.GetUUIDByOrgID(k.orgID, namespace+abstractPGName)
			// 适配 serverless pod
			podGroups, _ = simplejson.NewJson([]byte(fmt.Sprintf(`[{"uid": "%s","kind": "%s"}]`, uid, abstractPGType)))
		}
		ID := podGroups.GetIndex(0).Get("uid").MustString()
		if ID == "" {
			log.Infof("pod (%s) pod group not found", name)
			continue
		}
		kind := podGroups.GetIndex(0).Get("kind").MustString()
		if _, ok := podTypesMap[kind]; !ok {
			log.Infof("pod group (%s) type (%s) not support", name, kind)
			continue
		}
		hostIP := pData.Get("status").Get("hostIP").MustString()

		podRSLcuuid := ""
		podGroupLcuuid := ""
		podLcuuid := ""
		ID = common.IDGenerateUUID(k.orgID, ID)
		if gLcuuid, ok := k.rsLcuuidToPodGroupLcuuid[ID]; ok {
			podRSLcuuid = ID
			podGroupLcuuid = gLcuuid
		} else {
			if !k.podGroupLcuuids.Contains(ID) {
				log.Debugf("pod (%s) pod group not found", name)
				continue
			}
			podGroupLcuuid = ID
		}
		if kind == "StatefulSet" {
			generate_name := metaData.Get("generate_name").MustString()
			serialNumber := strings.TrimLeft(name, generate_name)
			podLcuuid = common.GetUUIDByOrgID(k.orgID, ID+serialNumber)
		} else {
			podLcuuid = common.IDGenerateUUID(k.orgID, uID)
		}
		conditions := pData.Get("status").Get("conditions")
		conditionStatus := []string{}
		for i := range conditions.MustArray() {
			cData := conditions.GetIndex(i).MustMap()
			cType := cData["type"].(string)
			if cType == "Ready" {
				cStatus := cData["status"].(string)
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
	log.Debug("get pods complete")
	return
}
