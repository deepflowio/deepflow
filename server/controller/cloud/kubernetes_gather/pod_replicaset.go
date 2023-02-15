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
	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"strings"

	"github.com/bitly/go-simplejson"
	mapset "github.com/deckarep/golang-set"
	uuid "github.com/satori/go.uuid"
)

func (k *KubernetesGather) getReplicaSetsAndReplicaSetControllers() (podRSs []model.PodReplicaSet, podRSCs []model.PodGroup, err error) {
	log.Debug("get replicasets,replicasetcontrollers starting")
	for _, r := range k.k8sInfo["*v1.ReplicaSet"] {
		rData, rErr := simplejson.NewJson([]byte(r))
		if rErr != nil {
			err = rErr
			log.Errorf("replicaset,replicasetcontroller initialization simplejson error: (%s)", rErr.Error())
			return
		}
		metaData, ok := rData.CheckGet("metadata")
		if !ok {
			log.Info("replicaset,replicasetcontroller metadata not found")
			continue
		}
		uID := metaData.Get("uid").MustString()
		if uID == "" {
			log.Info("replicaset,replicasetcontroller uid not found")
			continue
		}
		name := metaData.Get("name").MustString()
		if name == "" {
			log.Infof("replicaset,replicasetcontroller (%s) name not found", uID)
			continue
		}
		replicas := rData.Get("spec").Get("replicas").MustInt()
		if replicas == 0 {
			log.Debugf("replicaset,replicasetcontroller (%s) is inactive", name)
			continue
		}
		namespace := metaData.Get("namespace").MustString()
		namespaceLcuuid, ok := k.namespaceToLcuuid[namespace]
		if !ok {
			log.Infof("replicaset,replicasetcontroller (%s) namespace not found", name)
			continue
		}
		podGroups := metaData.Get("ownerReferences")
		podGroupLcuuid := podGroups.GetIndex(0).Get("uid").MustString()
		if len(podGroups.MustArray()) == 0 || podGroupLcuuid == "" {
			log.Infof("replicaset,replicasetcontroller (%s) pod group not found", name)
			continue
		}
		labels := metaData.Get("labels").MustMap()
		labelSlice := cloudcommon.StringInterfaceMapKVs(labels, ":")
		labelString := strings.Join(labelSlice, ", ")
		if !k.podGroupLcuuids.Contains(podGroupLcuuid) {
			podGroupLcuuid = uID
			// ReplicaSetController类型名称去掉最后的'-' + hash值
			targetIndex := strings.LastIndex(name, "-")
			newName := name[:targetIndex]
			label := "replicasetcontroller:" + namespace + ":" + name
			_, ok = k.nsLabelToGroupLcuuids[namespace+label]
			if ok {
				k.nsLabelToGroupLcuuids[namespace+label].Add(uID)
			} else {
				rscLcuuidsSet := mapset.NewSet()
				rscLcuuidsSet.Add(uID)
				k.nsLabelToGroupLcuuids[namespace+label] = rscLcuuidsSet
			}
			mLabels := rData.Get("spec").Get("selector").Get("matchLabels").MustMap()
			for key, v := range mLabels {
				nsLabel := namespace + key + "_" + v.(string)
				_, ok := k.nsLabelToGroupLcuuids[nsLabel]
				if ok {
					k.nsLabelToGroupLcuuids[nsLabel].Add(uID)
				} else {
					nsRSCLcuuidsSet := mapset.NewSet()
					nsRSCLcuuidsSet.Add(uID)
					k.nsLabelToGroupLcuuids[nsLabel] = nsRSCLcuuidsSet
				}
			}
			podRSC := model.PodGroup{
				Lcuuid:             uID,
				Name:               newName,
				Label:              labelString,
				Type:               common.POD_GROUP_REPLICASET_CONTROLLER,
				PodNum:             replicas,
				RegionLcuuid:       k.RegionUuid,
				AZLcuuid:           k.azLcuuid,
				PodNamespaceLcuuid: namespaceLcuuid,
				PodClusterLcuuid:   common.GetUUID(k.UuidGenerate, uuid.Nil),
			}
			podRSCs = append(podRSCs, podRSC)
		}
		podRS := model.PodReplicaSet{
			Lcuuid:             uID,
			Name:               name,
			PodNum:             replicas,
			Label:              labelString,
			PodGroupLcuuid:     podGroupLcuuid,
			RegionLcuuid:       k.RegionUuid,
			AZLcuuid:           k.azLcuuid,
			PodNamespaceLcuuid: namespaceLcuuid,
			PodClusterLcuuid:   common.GetUUID(k.UuidGenerate, uuid.Nil),
		}
		podRSs = append(podRSs, podRS)
		k.rsLcuuidToPodGroupLcuuid[uID] = podGroupLcuuid
	}
	log.Debug("get replicasets,replicasetcontrollers complete")
	return
}
