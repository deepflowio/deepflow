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
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (k *KubernetesGather) getReplicaSetsAndReplicaSetControllers() (podRSs []model.PodReplicaSet, podRSCs []model.PodGroup, podGroupConfigMapConnections []model.PodGroupConfigMapConnection, err error) {
	log.Debug("get replicasets,replicasetcontrollers starting", logger.NewORGPrefix(k.orgID))
	for _, r := range k.k8sEntries["*v1.ReplicaSet"] {
		rData, rErr := simplejson.NewJson(r)
		if rErr != nil {
			err = rErr
			log.Errorf("replicaset,replicasetcontroller initialization simplejson error: (%s)", rErr.Error(), logger.NewORGPrefix(k.orgID))
			return
		}
		metaData, ok := rData.CheckGet("metadata")
		if !ok {
			log.Info("replicaset,replicasetcontroller metadata not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		uID := metaData.Get("uid").MustString()
		if uID == "" {
			log.Info("replicaset,replicasetcontroller uid not found", logger.NewORGPrefix(k.orgID))
			continue
		}
		name := metaData.Get("name").MustString()
		if name == "" {
			log.Infof("replicaset,replicasetcontroller (%s) name not found", uID, logger.NewORGPrefix(k.orgID))
			continue
		}
		spec := rData.Get("spec")
		replicas := spec.Get("replicas").MustInt()
		if replicas == 0 {
			log.Debugf("replicaset,replicasetcontroller (%s) is inactive", name, logger.NewORGPrefix(k.orgID))
			continue
		}
		namespace := metaData.Get("namespace").MustString()
		namespaceLcuuid, ok := k.namespaceToLcuuid[namespace]
		if !ok {
			log.Infof("replicaset,replicasetcontroller (%s) namespace not found", name, logger.NewORGPrefix(k.orgID))
			continue
		}
		podGroups := metaData.Get("ownerReferences")
		podGroupLcuuid := podGroups.GetIndex(0).Get("uid").MustString()
		if len(podGroups.MustArray()) == 0 || podGroupLcuuid == "" {
			log.Infof("replicaset,replicasetcontroller (%s) pod group not found", name, logger.NewORGPrefix(k.orgID))
			continue
		}
		podGroupLcuuid = common.IDGenerateUUID(k.orgID, podGroupLcuuid)
		uLcuuid := common.IDGenerateUUID(k.orgID, uID)
		labelString := k.GetLabel(metaData.Get("labels").MustMap())
		if !k.podGroupLcuuids.Contains(podGroupLcuuid) {
			podGroupLcuuid = uLcuuid
			// ReplicaSetController类型名称去掉最后的'-' + hash值
			nName := name
			targetIndex := strings.LastIndex(name, "-")
			if targetIndex != -1 {
				nName = name[:targetIndex]
			}
			label := "replicasetcontroller:" + namespace + ":" + name
			_, ok = k.nsLabelToGroupLcuuids[namespace+label]
			if ok {
				k.nsLabelToGroupLcuuids[namespace+label].Add(uLcuuid)
			} else {
				rscLcuuidsSet := mapset.NewSet()
				rscLcuuidsSet.Add(uLcuuid)
				k.nsLabelToGroupLcuuids[namespace+label] = rscLcuuidsSet
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
					nsRSCLcuuidsSet := mapset.NewSet()
					nsRSCLcuuidsSet.Add(uLcuuid)
					k.nsLabelToGroupLcuuids[nsLabel] = nsRSCLcuuidsSet
				}
			}
			metaDataStr := k.simpleJsonMarshal(metaData)
			specStr := k.simpleJsonMarshal(spec)
			podRSCs = append(podRSCs, model.PodGroup{
				Lcuuid:             uLcuuid,
				Name:               nName,
				Metadata:           metaDataStr,
				MetadataHash:       cloudcommon.GenerateMD5Sum(metaDataStr),
				Spec:               specStr,
				SpecHash:           cloudcommon.GenerateMD5Sum(specStr),
				Label:              labelString,
				Type:               common.POD_GROUP_REPLICASET_CONTROLLER,
				PodNum:             replicas,
				RegionLcuuid:       k.RegionUUID,
				AZLcuuid:           k.azLcuuid,
				PodNamespaceLcuuid: namespaceLcuuid,
				PodClusterLcuuid:   k.podClusterLcuuid,
			})
			podGroupConfigMapConnections = append(podGroupConfigMapConnections, k.pgSpecGenerateConnections(namespace, name, uLcuuid, spec)...)
		}
		podRS := model.PodReplicaSet{
			Lcuuid:             uLcuuid,
			Name:               name,
			PodNum:             replicas,
			Label:              labelString,
			PodGroupLcuuid:     podGroupLcuuid,
			RegionLcuuid:       k.RegionUUID,
			AZLcuuid:           k.azLcuuid,
			PodNamespaceLcuuid: namespaceLcuuid,
			PodClusterLcuuid:   k.podClusterLcuuid,
		}
		podRSs = append(podRSs, podRS)
		k.rsLcuuidToPodGroupLcuuid[uLcuuid] = podGroupLcuuid
	}
	log.Debug("get replicasets,replicasetcontrollers complete", logger.NewORGPrefix(k.orgID))
	return
}
