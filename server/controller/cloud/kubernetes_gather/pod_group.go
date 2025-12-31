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
	"strings"

	"github.com/bitly/go-simplejson"
	mapset "github.com/deckarep/golang-set"
	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/kubernetes_gather/plugin"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (k *KubernetesGather) getPodGroups() (podGroups []model.PodGroup, podGroupConfigMapConnections []model.PodGroupConfigMapConnection, err error) {
	log.Debug("get podgroups starting", logger.NewORGPrefix(k.orgID))
	podControllers := [5][][]byte{}
	podControllers[0] = k.k8sEntries["*v1.Deployment"]
	podControllers[1] = k.k8sEntries["*v1.StatefulSet"]
	podControllers[1] = append(podControllers[1], k.k8sEntries["*v1.OpenGaussCluster"]...)
	podControllers[2] = k.k8sEntries["*v1.DaemonSet"]
	podControllers[3] = k.k8sEntries["*v1.CloneSet"]
	podControllers[4] = k.k8sEntries["*v1.Pod"]
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
			cData, cErr := simplejson.NewJson(c)
			if cErr != nil {
				err = cErr
				log.Errorf("podgroup initialization simplejson error: (%s)", cErr.Error(), logger.NewORGPrefix(k.orgID))
				return
			}
			metaData, ok := cData.CheckGet("metadata")
			if !ok {
				log.Info("podgroup metadata not found", logger.NewORGPrefix(k.orgID))
				continue
			}
			uID := metaData.Get("uid").MustString()
			if uID == "" {
				log.Info("podgroup uid not found", logger.NewORGPrefix(k.orgID))
				continue
			}
			name := metaData.Get("name").MustString()
			if name == "" {
				log.Infof("podgroup (%s) name not found", uID, logger.NewORGPrefix(k.orgID))
				continue
			}
			namespace := metaData.Get("namespace").MustString()
			if namespace == "" {
				log.Infof("podgroup (%s) namespace not found", name, logger.NewORGPrefix(k.orgID))
				continue
			}
			namespaceLcuuid, ok := k.namespaceToLcuuid[namespace]
			if !ok {
				log.Infof("podgroup (%s) namespace id not found", name, logger.NewORGPrefix(k.orgID))
				continue
			}
			spec := cData.Get("spec")
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
				if metaData.Get("ownerReferences").GetIndex(0).Get("kind").MustString() == "InPlaceSet" {
					uLcuuid = common.IDGenerateUUID(k.orgID, metaData.Get("ownerReferences").GetIndex(0).Get("uid").MustString())
					name = metaData.Get("ownerReferences").GetIndex(0).Get("name").MustString()
					if k.podGroupLcuuids.Contains(uLcuuid) {
						log.Debugf("inplaceset pod (%s) abstract workload already existed", name, logger.NewORGPrefix(k.orgID))
						continue
					}
					serviceType = common.POD_GROUP_DEPLOYMENT
					label = "inplaceset:" + namespace + ":" + name
				} else {
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
			mLabels := spec.GetPath("template", "metadata", "labels").MustMap()
			for key, v := range mLabels {
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
			labels := metaData.Get("labels").MustMap()
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

			containers := spec.GetPath("template", "spec", "containers")
			for i := range containers.MustArray() {
				container := containers.GetIndex(i)
				cPorts, ok := container.CheckGet("ports")
				if !ok {
					continue
				}
				for j := range cPorts.MustArray() {
					cPort := cPorts.GetIndex(j)
					cPortName, err := cPort.Get("name").String()
					if err != nil {
						continue
					}
					podTargetPorts[cPortName] = cPort.Get("containerPort").MustInt()
				}
			}
			networkMode := common.POD_GROUP_POD_NETWORK
			if spec.GetPath("template", "spec", "hostNetwork").MustBool() {
				networkMode = common.POD_GROUP_HOST_NETWORK
			}
			metaDataStr := k.simpleJsonMarshal(metaData)
			specStr := k.simpleJsonMarshal(spec)
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
				PodNum:             spec.Get("replicas").MustInt(),
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
	for _, r := range k.k8sEntries["*v1.ReplicationController"] {
		podTargetPorts := map[string]int{}
		rData, rErr := simplejson.NewJson(r)
		if rErr != nil {
			err = rErr
			log.Errorf("replicationcontroller initialization simplejson error: (%s)", rErr.Error(), logger.NewORGPrefix(k.orgID))
			return
		}
		metaData, ok := rData.CheckGet("metadata")
		if !ok {
			log.Info("replicationcontroller metadata not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		uID := metaData.Get("uid").MustString()
		if uID == "" {
			log.Info("replicationcontroller uid not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		name := metaData.Get("name").MustString()
		if name == "" {
			log.Infof("replicationcontroller (%s) name not found", uID, logger.NewORGPrefix(k.orgID))
			continue
		}
		spec := rData.Get("spec")
		uLcuuid := common.IDGenerateUUID(k.orgID, uID)
		namespace := metaData.Get("namespace").MustString()
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
		labels := spec.GetPath("template", "metadata", "labels").MustMap()
		for key, v := range labels {
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
		containers := spec.GetPath("template", "spec", "containers")
		for i := range containers.MustArray() {
			container := containers.GetIndex(i)
			cPorts, ok := container.CheckGet("ports")
			if !ok {
				continue
			}
			for j := range cPorts.MustArray() {
				cPort := cPorts.GetIndex(j)
				cPortName, err := cPort.Get("name").String()
				if err != nil {
					continue
				}
				podTargetPorts[cPortName] = cPort.Get("containerPort").MustInt()
			}
		}
		metaDataStr := k.simpleJsonMarshal(metaData)
		specStr := k.simpleJsonMarshal(spec)
		podRC := model.PodGroup{
			Lcuuid:             uLcuuid,
			Name:               name,
			Metadata:           metaDataStr,
			MetadataHash:       cloudcommon.GenerateMD5Sum(metaDataStr),
			Spec:               specStr,
			SpecHash:           cloudcommon.GenerateMD5Sum(specStr),
			Label:              k.GetLabel(labels),
			Type:               serviceType,
			PodNum:             spec.Get("replicas").MustInt(),
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
