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

	"github.com/bitly/go-simplejson"
	mapset "github.com/deckarep/golang-set"
	cloudcommon "github.com/deepflowys/deepflow/server/controller/cloud/common"
	"github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/common"
	uuid "github.com/satori/go.uuid"
)

func (k *KubernetesGather) getPodGroups() (podGroups []model.PodGroup, err error) {
	log.Debug("get podgroups starting")
	podControllers := [4][]string{}
	podControllers[0] = k.k8sInfo["*v1.Deployment"]
	podControllers[1] = k.k8sInfo["*v1.StatefulSet"]
	podControllers[2] = k.k8sInfo["*v1.DaemonSet"]
	podControllers[3] = k.k8sInfo["*v1.Pod"]
	pgNameToTypeID := map[string]int{
		"deployment":            common.POD_GROUP_DEPLOYMENT,
		"statefulset":           common.POD_GROUP_STATEFULSET,
		"replicaset":            common.POD_GROUP_RC,
		"daemonset":             common.POD_GROUP_DAEMON_SET,
		"replicationcontroller": common.POD_GROUP_REPLICASET_CONTROLLER,
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
			label := "statefulset" + namespace + ":" + name
			replicas := cData.Get("spec").Get("replicas").MustInt()
			switch t {
			case 0:
				serviceType = common.POD_GROUP_DEPLOYMENT
				label = "deployment" + namespace + ":" + name
			case 2:
				replicas = 0
				serviceType = common.POD_GROUP_DAEMON_SET
				label = "daemonset" + namespace + ":" + name
			case 3:
				replicas = 0
				oReferences := metaData.Get("ownerReferences")
				if len(oReferences.MustArray()) == 0 {
					podType := "Deployment"
					key := metaData.Get("generateName").MustString()
					if pTempHash, ok := metaData.Get("labels").CheckGet("pod-template-hash"); ok {
						if key == "" {
							key = pTempHash.MustString() + "-"
						}
						podType = "Deployment"
					} else if cReHash, ok := metaData.Get("labels").CheckGet("controller-revision-hash"); ok {
						if key == "" {
							targetIndex := strings.LastIndex(cReHash.MustString(), "-")
							key = cReHash.MustString()[:targetIndex+1]
						}
						podType = "StatefulSet"
					} else {
						if key == "" {
							log.Debugf("pod (%s) abstract workload target hash and generate name not found", name)
							continue
						}
					}
					pNameSlice := strings.Split(name, "-"+key)
					if len(pNameSlice) != 2 {
						log.Debugf("pod name (%s) not split by (%s)", name, key)
						continue
					}
					uid := common.GetUUID(namespace+pNameSlice[0], uuid.Nil)
					oReferences, _ = simplejson.NewJson([]byte(fmt.Sprintf(`[{"uid": "%s","kind": "%s"}]`, uid, podType)))
					if k.podGroupLcuuids.Contains(uid) {
						log.Debugf("podgroup (%s) abstract workload already existed", name)
						continue
					}
					name = pNameSlice[0]
				}
				uID = oReferences.GetIndex(0).Get("uid").MustString()
				if uID == "" {
					log.Info("abstract workload podgroup uid not found")
					continue
				}
				typeName := strings.ToLower(oReferences.GetIndex(0).Get("kind").MustString())
				serviceType, ok = pgNameToTypeID[typeName]
				if !ok {
					serviceType = 1
				}
				label = typeName + ":" + namespace + ":" + name
			}

			_, ok = k.nsLabelToGroupLcuuids[namespace+label]
			if ok {
				k.nsLabelToGroupLcuuids[namespace+label].Add(uID)
			} else {
				groupIDsSet := mapset.NewSet()
				groupIDsSet.Add(uID)
				k.nsLabelToGroupLcuuids[namespace+label] = groupIDsSet
			}
			mLabels := cData.Get("spec").Get("selector").Get("matchLabels").MustMap()
			for key, v := range mLabels {
				nsLabel := namespace + key + "_" + v.(string)
				_, ok := k.nsLabelToGroupLcuuids[nsLabel]
				if ok {
					k.nsLabelToGroupLcuuids[nsLabel].Add(uID)
				} else {
					nsGroupIDsSet := mapset.NewSet()
					nsGroupIDsSet.Add(uID)
					k.nsLabelToGroupLcuuids[nsLabel] = nsGroupIDsSet
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
			labels := metaData.Get("labels").MustMap()
			labelSlice := cloudcommon.StringInterfaceMapKVs(labels, ":")
			labelString := strings.Join(labelSlice, ", ")
			podGroup := model.PodGroup{
				Lcuuid:             uID,
				Name:               name,
				Label:              labelString,
				Type:               serviceType,
				PodNum:             replicas,
				PodNamespaceLcuuid: namespaceLcuuid,
				AZLcuuid:           k.azLcuuid,
				RegionLcuuid:       k.RegionUuid,
				PodClusterLcuuid:   common.GetUUID(k.UuidGenerate, uuid.Nil),
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
		labels := rData.Get("spec").Get("selector").MustMap()
		for key, v := range labels {
			nsLabel := namespace + key + "_" + v.(string)
			_, ok := k.nsLabelToGroupLcuuids[nsLabel]
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
		labelSlice := cloudcommon.StringInterfaceMapKVs(labels, ":")
		labelString := strings.Join(labelSlice, ",")
		podNum := rData.Get("spec").Get("replicas").MustInt()
		podRC := model.PodGroup{
			Lcuuid:             uID,
			Name:               name,
			Label:              labelString,
			Type:               serviceType,
			PodNum:             podNum,
			RegionLcuuid:       k.RegionUuid,
			AZLcuuid:           k.azLcuuid,
			PodNamespaceLcuuid: namespaceLcuuid,
			PodClusterLcuuid:   common.GetUUID(k.UuidGenerate, uuid.Nil),
		}
		podRCs = append(podRCs, podRC)
		k.podGroupLcuuids.Add(uID)
		k.pgLcuuidTopodTargetPorts[uID] = podTargetPorts
	}
	log.Debug("get replicationcontrollers complete")
	return
}
