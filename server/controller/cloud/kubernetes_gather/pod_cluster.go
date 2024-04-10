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
	"errors"

	"github.com/bitly/go-simplejson"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (k *KubernetesGather) getPodCluster() (model.PodCluster, error) {
	log.Debug("get pod cluster starting")
	vInfo, ok := k.k8sInfo["*version.Info"]
	if !ok || len(vInfo) == 0 {
		return model.PodCluster{}, errors.New("not found k8s version info")
	}

	vJson, vErr := simplejson.NewJson([]byte(vInfo[0]))
	if vErr != nil {
		log.Errorf("pod cluster initialization version json error: (%s)", vErr.Error())
		return model.PodCluster{}, vErr
	}
	version := vJson.Get("gitVersion").MustString()
	if version == "" {
		return model.PodCluster{}, errors.New("not found k8s gitversion")
	}
	k.podClusterLcuuid = common.GetUUIDByOrgID(k.orgID, k.UuidGenerate)
	podCluster := model.PodCluster{
		Lcuuid:       k.podClusterLcuuid,
		Version:      cloudcommon.K8S_VERSION_PREFIX + " " + version,
		Name:         k.Name,
		VPCLcuuid:    k.VPCUUID,
		AZLcuuid:     k.azLcuuid,
		RegionLcuuid: k.RegionUUID,
	}
	log.Debug("get pod cluster complete")
	return podCluster, nil
}
