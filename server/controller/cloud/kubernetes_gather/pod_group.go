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

package kubernetes_gather

import (
	"strings"

	"github.com/bitly/go-simplejson"
	mapset "github.com/deckarep/golang-set"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	uuid "github.com/satori/go.uuid"
)

func (k *KubernetesGather) getPodGroups() (podGroups []model.PodGroup, err error) {
	log.Debug("get podgroups starting")
	podControllers := [5][]string{}
	podControllers[0] = k.k8sInfo["*v1.Deployment"]
	podControllers[1] = k.k8sInfo["*v1.StatefulSet"]
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
			cData, cErr := simplejson.NewJson([]byte(c))
			if cErr != nil {
				err = cErr
				log.Errorf("podgroup initialization simplejson error: (%s)", cErr.Error())
				return
			}
			metaData, ok := cData.CheckGet("metadata")
			if !ok {
				log.Info("podgroup metadata not found")
				continue
			}
			uID := metaData.Get("uid").MustString()
			if uID == "" {
				log.Info("podgroup uid not found")
				continue
			}
			name := metaData.Get("name").MustString()
			if name == "" {
				log.Infof("podgroup (%s) name not found", uID)
				continue
			}
			namespace := metaData.Get("namespace").MustString()
			if namespace == "" {
				log.Infof("podgroup (%s) namespace not found", name)
				continue
			}
			namespaceLcuuid, ok := k.namespaceToLcuuid[namespace]
			if !ok {
				log.Infof("podgroup (%s) namespace id not found", name)
				continue
			}
			serviceType := common.POD_GROUP_STATEFULSET
			label := "statefulset:" + namespace + ":" + name
			replicas := cData.Get("spec").Get("replicas").MustInt()
			switch t {
			case 0:
				serviceType = common.POD_GROUP_DEPLOYMENT
				label = "deployment:" + namespace + ":" + name
			case 2:
				replicas = 0
				serviceType = common.POD_GROUP_DAEMON_SET
				label = "daemonset:" + namespace + ":" + name
			case 3:
				serviceType = common.POD_GROUP_CLONESET
				label = "cloneset:" + namespace + ":" + name
			case 4:
				replicas = 0
				if metaData.Get("ownerReferences").GetIndex(0).Get("kind").MustString() == "InPlaceSet" {
					uID = metaData.Get("ownerReferences").GetIndex(0).Get("uid").MustString()
					name = metaData.Get("ownerReferences").GetIndex(0).Get("name").MustString()
					if k.podGroupLcuuids.Contains(uID) {
						log.Debugf("inplaceset pod (%s) abstract workload already existed", name)
						continue
					}
					serviceType = common.POD_GROUP_DEPLOYMENT
					label = "inplaceset:" + namespace + ":" + name
				} else {
					providerType := metaData.Get("labels").Get("virtual-kubelet.io/provider-cluster-type").MustString()
					if providerType != "serverless" && providerType != "proprietary" {
						log.Debugf("sci pod (%s) type (%s) not support", name, providerType)
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
						log.Debugf("sci pod (%s) abstract pod group not found provider resource name", name)
						continue
					}
					abstractPGName := resourceName
					targetIndex := strings.LastIndex(resourceName, "-")
					if targetIndex != -1 {
						abstractPGName = resourceName[:targetIndex]
					}
					uID = common.GetUUID(namespace+abstractPGName, uuid.Nil)
					if k.podGroupLcuuids.Contains(uID) {
						log.Debugf("sci pod (%s) abstract workload already existed", name)
						continue
					}
					typeName := strings.ToLower(abstractPGType)
					serviceType = pgNameToTypeID[typeName]
					label = typeName + ":" + namespace + ":" + abstractPGName
					name = abstractPGName
				}
			}

			_, ok = k.nsLabelToGroupLcuuids[namespace+label]
			if ok {
				k.nsLabelToGroupLcuuids[namespace+label].Add(uID)
			} else {
				groupIDsSet := mapset.NewSet()
				groupIDsSet.Add(uID)
				k.nsLabelToGroupLcuuids[namespace+label] = groupIDsSet
			}
			mLabels := cData.GetPath("spec", "template", "metadata", "labels").MustMap()
			for key, v := range mLabels {
				vString, ok := v.(string)
				if !ok {
					vString = ""
				}
				nsLabel := namespace + key + "_" + vString
				_, ok = k.nsLabelToGroupLcuuids[nsLabel]
				if ok {
					k.nsLabelToGroupLcuuids[nsLabel].Add(uID)
				} else {
					nsGroupIDsSet := mapset.NewSet()
					nsGroupIDsSet.Add(uID)
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
					k.nsLabelToGroupLcuuids[nsL].Add(uID)
				} else {
					nsGIDsSet := mapset.NewSet()
					nsGIDsSet.Add(uID)
					k.nsLabelToGroupLcuuids[nsL] = nsGIDsSet
				}
			}

			containers := cData.Get("spec").Get("template").Get("spec").Get("containers")
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
			podGroup := model.PodGroup{
				Lcuuid:             uID,
				Name:               name,
				Label:              k.GetLabel(labels),
				Type:               serviceType,
				PodNum:             replicas,
				PodNamespaceLcuuid: namespaceLcuuid,
				AZLcuuid:           k.azLcuuid,
				RegionLcuuid:       k.RegionUuid,
				PodClusterLcuuid:   k.podClusterLcuuid,
			}
			podGroups = append(podGroups, podGroup)
			k.podGroupLcuuids.Add(uID)
			k.pgLcuuidTopodTargetPorts[uID] = podTargetPorts
		}
	}
	log.Debug("get podgroups complete")
	return
}

func (k *KubernetesGather) getPodReplicationControllers() (podRCs []model.PodGroup, err error) {
	log.Debug("get replicationcontrollers starting")
	for _, r := range k.k8sInfo["*v1.ReplicationController"] {
		podTargetPorts := map[string]int{}
		rData, rErr := simplejson.NewJson([]byte(r))
		if rErr != nil {
			err = rErr
			log.Errorf("replicationcontroller initialization simplejson error: (%s)", rErr.Error())
			return
		}
		metaData, ok := rData.CheckGet("metadata")
		if !ok {
			log.Info("replicationcontroller metadata not found")
			continue
		}
		uID := metaData.Get("uid").MustString()
		if uID == "" {
			log.Info("replicationcontroller uid not found")
			continue
		}
		name := metaData.Get("name").MustString()
		if name == "" {
			log.Infof("replicationcontroller (%s) name not found", uID)
			continue
		}
		namespace := metaData.Get("namespace").MustString()
		namespaceLcuuid, ok := k.namespaceToLcuuid[namespace]
		if !ok {
			log.Infof("replicationcontroller (%s) namespace not found", name)
			continue
		}
		label := "replicationcontroller:" + namespace + ":" + name
		serviceType := common.POD_GROUP_RC
		_, ok = k.nsLabelToGroupLcuuids[namespace+label]
		if ok {
			k.nsLabelToGroupLcuuids[namespace+label].Add(uID)
		} else {
			rcLcuuidsSet := mapset.NewSet()
			rcLcuuidsSet.Add(uID)
			k.nsLabelToGroupLcuuids[namespace+label] = rcLcuuidsSet
		}
		labels := rData.GetPath("spec", "template", "metadata", "labels").MustMap()
		for key, v := range labels {
			vString, ok := v.(string)
			if !ok {
				continue
			}
			nsLabel := namespace + key + "_" + vString
			_, ok = k.nsLabelToGroupLcuuids[nsLabel]
			if ok {
				k.nsLabelToGroupLcuuids[nsLabel].Add(uID)
			} else {
				nsRCLcuuidsSet := mapset.NewSet()
				nsRCLcuuidsSet.Add(uID)
				k.nsLabelToGroupLcuuids[nsLabel] = nsRCLcuuidsSet
			}
		}
		containers := rData.Get("spec").Get("template").Get("spec").Get("containers")
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

		podNum := rData.Get("spec").Get("replicas").MustInt()
		podRC := model.PodGroup{
			Lcuuid:             uID,
			Name:               name,
			Label:              k.GetLabel(labels),
			Type:               serviceType,
			PodNum:             podNum,
			RegionLcuuid:       k.RegionUuid,
			AZLcuuid:           k.azLcuuid,
			PodNamespaceLcuuid: namespaceLcuuid,
			PodClusterLcuuid:   k.podClusterLcuuid,
		}
		podRCs = append(podRCs, podRC)
		k.podGroupLcuuids.Add(uID)
		k.pgLcuuidTopodTargetPorts[uID] = podTargetPorts
	}
	log.Debug("get replicationcontrollers complete")
	return
}
