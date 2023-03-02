/*
 * Copyright (c) 2022 Yunshan Networks
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
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	uuid "github.com/satori/go.uuid"
)

func (k *KubernetesGather) getPods() (pods []model.Pod, nodes []model.PodNode, err error) {
	log.Debug("get pods starting")
	podTypesMap := map[string]bool{
		"DaemonSet":             false,
		"Deployment":            false,
		"InPlaceSet":            false,
		"ReplicaSet":            false,
		"StatefulSet":           false,
		"ReplicationController": false,
	}
	abstractNodes := map[string]int{}
	for _, p := range k.k8sInfo["*v1.Pod"] {
		pData, pErr := simplejson.NewJson([]byte(p))
		if pErr != nil {
			err = pErr
			log.Errorf("pod initialization simplejson error: (%s)", pErr.Error())
			return
		}
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
			targetIndex := strings.LastIndex(resourceName, "-")
			abstractPGName := resourceName[:targetIndex]
			uid := common.GetUUID(namespace+abstractPGName, uuid.Nil)
			// 适配平安 serverless pod, 需要抽象出一个对应的 node , 在这里添加一个参考值 abstract 作为判断标志
			podGroups, _ = simplejson.NewJson([]byte(fmt.Sprintf(`[{"uid": "%s","kind": "%s","abstract": true}]`, uid, abstractPGType)))
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
		nodeLcuuid, ok := k.nodeIPToLcuuid[hostIP]
		if !ok {
			if podGroups.GetIndex(0).Get("abstract").MustBool() {
				abstractNodes[hostIP] = 0
			} else {
				log.Infof("pod (%s) hostIP (%s) not found in node", hostIP, name)
				continue
			}
		}

		podRSLcuuid := ""
		podGroupLcuuid := ""
		podLcuuid := ""
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
			podLcuuid = common.GetUUID(ID+serialNumber, uuid.Nil)
		} else {
			podLcuuid = uID
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
		labelSlice := cloudcommon.StringInterfaceMapKVs(labels, ":")
		labelString := strings.Join(labelSlice, ", ")
		pod := model.Pod{
			Lcuuid:              podLcuuid,
			Name:                name,
			State:               status,
			VPCLcuuid:           k.VPCUuid,
			Label:               labelString,
			PodReplicaSetLcuuid: podRSLcuuid,
			PodNodeLcuuid:       nodeLcuuid,
			PodGroupLcuuid:      podGroupLcuuid,
			PodNamespaceLcuuid:  namespaceLcuuid,
			CreatedAt:           created,
			AZLcuuid:            k.azLcuuid,
			RegionLcuuid:        k.RegionUuid,
			PodClusterLcuuid:    common.GetUUID(k.UuidGenerate, uuid.Nil),
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

	for nodeIP := range abstractNodes {
		podClusterLcuuid := common.GetUUID(k.UuidGenerate, uuid.Nil)
		nodes = append(nodes, model.PodNode{
			Lcuuid:           common.GetUUID(nodeIP+podClusterLcuuid, uuid.Nil),
			Name:             nodeIP,
			Type:             common.POD_NODE_TYPE_NODE,
			ServerType:       common.POD_NODE_SERVER_TYPE_HOST,
			State:            common.POD_NODE_STATE_NORMAL,
			IP:               nodeIP,
			VPCLcuuid:        k.VPCUuid,
			AZLcuuid:         k.azLcuuid,
			RegionLcuuid:     k.RegionUuid,
			PodClusterLcuuid: common.GetUUID(k.UuidGenerate, uuid.Nil),
		})
	}
	log.Debug("get pods complete")
	return
}
