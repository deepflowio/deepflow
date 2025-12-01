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
	"strings"

	mapset "github.com/deckarep/golang-set"
	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/plugin"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

// rawMessageToMap 将 json.RawMessage 解析为 map[string]interface{}
func rawMessageToMap(raw json.RawMessage) (map[string]interface{}, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (k *KubernetesGather) getPodGroups() (podGroups []model.PodGroup, podGroupConfigMapConnections []model.PodGroupConfigMapConnection, err error) {
	log.Debug("get podgroups starting", logger.NewORGPrefix(k.orgID))
	podControllers := [5][]string{}
	podControllers[0] = k.k8sInfo["*v1.Deployment"]
	podControllers[1] = k.k8sInfo["*v1.StatefulSet"]
	podControllers[1] = append(podControllers[1], k.k8sInfo["*v1.OpenGaussCluster"]...)
	podControllers[2] = k.k8sInfo["*v1.DaemonSet"]
	podControllers[3] = k.k8sInfo["*v1.CloneSet"]
	podControllers[4] = k.k8sInfo["*v1.Pod"]
	pgNameToTypeID := map[string]int{
		"deployment":            common.POD_GROUP_DEPLOYMENT,
		"statefulset":           common.POD_GROUP_STATEFULSET,
		"replicaset":            common.POD_GROUP_REPLICASET_CONTROLLER,
		"daemonset":             common.POD_GROUP_DAEMON_SET,
		"replicationcontroller": common.POD_GROUP_RC,
		"cloneset":              common.POD_GROUP_CLONESET,
	}
	for t, podController := range podControllers {
		for _, c := range podController {
			podTargetPorts := map[string]int{}
			cRaw := json.RawMessage(c)
			cData, cErr := rawMessageToMap(cRaw)
			if cErr != nil {
				err = cErr
				log.Errorf("podgroup initialization json error: (%s)", cErr.Error(), logger.NewORGPrefix(k.orgID))
				return
			}
			metaData, ok := getJSONMap(cData, "metadata")
			if !ok {
				log.Info("podgroup metadata not found", logger.NewORGPrefix(k.orgID))
				continue
			}
			uID := getJSONString(metaData, "uid")
			if uID == "" {
				log.Info("podgroup uid not found", logger.NewORGPrefix(k.orgID))
				continue
			}
			name := getJSONString(metaData, "name")
			if name == "" {
				log.Infof("podgroup (%s) name not found", uID, logger.NewORGPrefix(k.orgID))
				continue
			}
			namespace := getJSONString(metaData, "namespace")
			if namespace == "" {
				log.Infof("podgroup (%s) namespace not found", name, logger.NewORGPrefix(k.orgID))
				continue
			}
			namespaceLcuuid, ok := k.namespaceToLcuuid[namespace]
			if !ok {
				log.Infof("podgroup (%s) namespace id not found", name, logger.NewORGPrefix(k.orgID))
				continue
			}
			spec, _ := getJSONMap(cData, "spec")
			metaDataStr := k.simpleJsonMarshal(metaData)
			specStr := k.simpleJsonMarshal(spec)
			uLcuuid := common.IDGenerateUUID(k.orgID, uID)
			var serviceType int
			var label string
			switch t {
			case 0:
				serviceType = common.POD_GROUP_DEPLOYMENT
				label = "deployment:" + namespace + ":" + name
			case 1:
				serviceType = common.POD_GROUP_STATEFULSET
				label = "statefulset:" + namespace + ":" + name
			case 2:
				serviceType = common.POD_GROUP_DAEMON_SET
				label = "daemonset:" + namespace + ":" + name
			case 3:
				serviceType = common.POD_GROUP_CLONESET
				label = "cloneset:" + namespace + ":" + name
			case 4:
				ownerRefs, _ := getJSONArray(metaData, "ownerReferences")
				isInPlaceSet := false
				if len(ownerRefs) > 0 {
					if ownerRef, ok := ownerRefs[0].(map[string]interface{}); ok {
						if getJSONString(ownerRef, "kind") == "InPlaceSet" {
							isInPlaceSet = true
							uLcuuid = common.IDGenerateUUID(k.orgID, getJSONString(ownerRef, "uid"))
							name = getJSONString(ownerRef, "name")
							if k.podGroupLcuuids.Contains(uLcuuid) {
								log.Debugf("inplaceset pod (%s) abstract workload already existed", name, logger.NewORGPrefix(k.orgID))
								continue
							}
							serviceType = common.POD_GROUP_DEPLOYMENT
							label = "inplaceset:" + namespace + ":" + name
						}
					}
				}
				if !isInPlaceSet {
					// when certain Pods do not have a corresponding workload or the corresponding workload is not supported,
					// the lua plugin can be used to abstract the name and type of the workload according to the pod information
					// 当某些 pod 因为缺少对应的工作负载或对应的工作负载不被支持的时候，
					// 可以通过 lua 插件根据 pod 的信息来抽象出符合规则的工作负载名称和类型
					abstractPGType, abstractPGName, err := plugin.GeneratePodGroup(k.orgID, k.db, metaData)
					if err != nil {
						log.Warningf("pod (%s) abstract pod group failed: (%s)", name, err.Error(), logger.NewORGPrefix(k.orgID))
						continue
					}
					if abstractPGType == "" || abstractPGName == "" {
						log.Debugf("pod (%s) abstract not found pod group type (%s) or name (%s)", name, abstractPGType, abstractPGName, logger.NewORGPrefix(k.orgID))
						continue
					}

					typeName := strings.ToLower(abstractPGType)
					serviceType, ok = pgNameToTypeID[typeName]
					if !ok {
						log.Infof("pod (%s) abstract workload type (%s) not support", name, abstractPGType, logger.NewORGPrefix(k.orgID))
						continue
					}

					abstractUID := common.GetUUIDByOrgID(k.orgID, namespace+abstractPGName)
					k.podLcuuidToPGInfo[uID] = [2]string{abstractUID, abstractPGType}
					uLcuuid = common.IDGenerateUUID(k.orgID, abstractUID)
					if k.podGroupLcuuids.Contains(uLcuuid) {
						log.Debugf("pod (%s) abstract workload already existed", name, logger.NewORGPrefix(k.orgID))
						continue
					}
					label = typeName + ":" + namespace + ":" + abstractPGName
					name = abstractPGName
				}
			}

			_, ok = k.nsLabelToGroupLcuuids[namespace+label]
			if ok {
				k.nsLabelToGroupLcuuids[namespace+label].Add(uLcuuid)
			} else {
				groupIDsSet := mapset.NewSet()
				groupIDsSet.Add(uLcuuid)
				k.nsLabelToGroupLcuuids[namespace+label] = groupIDsSet
			}
			templateLabels := getJSONPath(spec, "template", "metadata", "labels")
			if templateLabels != nil {
				for key, v := range templateLabels {
					vString, ok := v.(string)
					if !ok {
						vString = ""
					}
					nsLabel := namespace + key + "_" + vString
					_, ok = k.nsLabelToGroupLcuuids[nsLabel]
					if ok {
						k.nsLabelToGroupLcuuids[nsLabel].Add(uLcuuid)
					} else {
						nsGroupIDsSet := mapset.NewSet()
						nsGroupIDsSet.Add(uLcuuid)
						k.nsLabelToGroupLcuuids[nsLabel] = nsGroupIDsSet
					}
				}
			}
			labels, _ := getJSONMap(metaData, "labels")
			for key, v := range labels {
				vString, ok := v.(string)
				if !ok {
					continue
				}
				nsL := namespace + key + "_" + vString
				_, ok = k.nsLabelToGroupLcuuids[nsL]
				if ok {
					k.nsLabelToGroupLcuuids[nsL].Add(uLcuuid)
				} else {
					nsGIDsSet := mapset.NewSet()
					nsGIDsSet.Add(uLcuuid)
					k.nsLabelToGroupLcuuids[nsL] = nsGIDsSet
				}
			}

			templateSpec := getJSONPath(spec, "template", "spec")
			if templateSpec != nil {
				containers, _ := getJSONArray(templateSpec, "containers")
				for _, containerInterface := range containers {
					container, ok := containerInterface.(map[string]interface{})
					if !ok {
						continue
					}
					ports, _ := getJSONArray(container, "ports")
					for _, portInterface := range ports {
						port, ok := portInterface.(map[string]interface{})
						if !ok {
							continue
						}
						cPortName := getJSONString(port, "name")
						if cPortName == "" {
							continue
						}
						podTargetPorts[cPortName] = getJSONInt(port, "containerPort")
					}
				}
			}
			networkMode := common.POD_GROUP_POD_NETWORK
			if templateSpec != nil && getJSONBool(templateSpec, "hostNetwork") {
				networkMode = common.POD_GROUP_HOST_NETWORK
			}
			podGroup := model.PodGroup{
				Lcuuid:             uLcuuid,
				Name:               name,
				Metadata:           metaDataStr,
				MetadataHash:       cloudcommon.GenerateMD5Sum(metaDataStr),
				Spec:               specStr,
				SpecHash:           cloudcommon.GenerateMD5Sum(specStr),
				Label:              k.GetLabel(labels),
				NetworkMode:        networkMode,
				Type:               serviceType,
				PodNum:             getJSONInt(spec, "replicas"),
				PodNamespaceLcuuid: namespaceLcuuid,
				AZLcuuid:           k.azLcuuid,
				RegionLcuuid:       k.RegionUUID,
				PodClusterLcuuid:   k.podClusterLcuuid,
			}
			podGroups = append(podGroups, podGroup)
			k.podGroupLcuuids.Add(uLcuuid)
			k.pgLcuuidTopodTargetPorts[uLcuuid] = podTargetPorts
			podGroupConfigMapConnections = append(podGroupConfigMapConnections, k.pgSpecGenerateConnections(namespace, name, uLcuuid, spec)...)
		}
	}
	log.Debug("get podgroups complete", logger.NewORGPrefix(k.orgID))
	return
}

func (k *KubernetesGather) getPodReplicationControllers() (podRCs []model.PodGroup, podGroupConfigMapConnections []model.PodGroupConfigMapConnection, err error) {
	log.Debug("get replicationcontrollers starting", logger.NewORGPrefix(k.orgID))
	for _, r := range k.k8sInfo["*v1.ReplicationController"] {
		podTargetPorts := map[string]int{}
		rRaw := json.RawMessage(r)
		rData, rErr := rawMessageToMap(rRaw)
		if rErr != nil {
			err = rErr
			log.Errorf("replicationcontroller initialization json error: (%s)", rErr.Error(), logger.NewORGPrefix(k.orgID))
			return
		}
		metaData, ok := getJSONMap(rData, "metadata")
		if !ok {
			log.Info("replicationcontroller metadata not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		uID := getJSONString(metaData, "uid")
		if uID == "" {
			log.Info("replicationcontroller uid not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		name := getJSONString(metaData, "name")
		if name == "" {
			log.Infof("replicationcontroller (%s) name not found", uID, logger.NewORGPrefix(k.orgID))
			continue
		}
		spec, _ := getJSONMap(rData, "spec")
		metaDataStr := k.simpleJsonMarshal(metaData)
		specStr := k.simpleJsonMarshal(spec)
		uLcuuid := common.IDGenerateUUID(k.orgID, uID)
		namespace := getJSONString(metaData, "namespace")
		namespaceLcuuid, ok := k.namespaceToLcuuid[namespace]
		if !ok {
			log.Infof("replicationcontroller (%s) namespace not found", name, logger.NewORGPrefix(k.orgID))
			continue
		}
		label := "replicationcontroller:" + namespace + ":" + name
		serviceType := common.POD_GROUP_RC
		_, ok = k.nsLabelToGroupLcuuids[namespace+label]
		if ok {
			k.nsLabelToGroupLcuuids[namespace+label].Add(uLcuuid)
		} else {
			rcLcuuidsSet := mapset.NewSet()
			rcLcuuidsSet.Add(uLcuuid)
			k.nsLabelToGroupLcuuids[namespace+label] = rcLcuuidsSet
		}
		templateLabels := getJSONPath(spec, "template", "metadata", "labels")
		if templateLabels != nil {
			for key, v := range templateLabels {
				vString, ok := v.(string)
				if !ok {
					continue
				}
				nsLabel := namespace + key + "_" + vString
				_, ok = k.nsLabelToGroupLcuuids[nsLabel]
				if ok {
					k.nsLabelToGroupLcuuids[nsLabel].Add(uLcuuid)
				} else {
					nsRCLcuuidsSet := mapset.NewSet()
					nsRCLcuuidsSet.Add(uLcuuid)
					k.nsLabelToGroupLcuuids[nsLabel] = nsRCLcuuidsSet
				}
			}
		}
		templateSpec := getJSONPath(spec, "template", "spec")
		if templateSpec != nil {
			containers, _ := getJSONArray(templateSpec, "containers")
			for _, containerInterface := range containers {
				container, ok := containerInterface.(map[string]interface{})
				if !ok {
					continue
				}
				ports, _ := getJSONArray(container, "ports")
				for _, portInterface := range ports {
					port, ok := portInterface.(map[string]interface{})
					if !ok {
						continue
					}
					cPortName := getJSONString(port, "name")
					if cPortName == "" {
						continue
					}
					podTargetPorts[cPortName] = getJSONInt(port, "containerPort")
				}
			}
		}
		podRC := model.PodGroup{
			Lcuuid:             uLcuuid,
			Name:               name,
			Metadata:           metaDataStr,
			MetadataHash:       cloudcommon.GenerateMD5Sum(metaDataStr),
			Spec:               specStr,
			SpecHash:           cloudcommon.GenerateMD5Sum(specStr),
			Label:              k.GetLabel(templateLabels),
			Type:               serviceType,
			PodNum:             getJSONInt(spec, "replicas"),
			RegionLcuuid:       k.RegionUUID,
			AZLcuuid:           k.azLcuuid,
			PodNamespaceLcuuid: namespaceLcuuid,
			PodClusterLcuuid:   k.podClusterLcuuid,
		}
		podRCs = append(podRCs, podRC)
		k.podGroupLcuuids.Add(uLcuuid)
		k.pgLcuuidTopodTargetPorts[uLcuuid] = podTargetPorts
		podGroupConfigMapConnections = append(podGroupConfigMapConnections, k.pgSpecGenerateConnections(namespace, name, uLcuuid, spec)...)
	}
	log.Debug("get replicationcontrollers complete", logger.NewORGPrefix(k.orgID))
	return
}
