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
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"

	"github.com/bitly/go-simplejson"
	uuid "github.com/satori/go.uuid"
)

func (k *KubernetesGather) getPodCluster() (model.PodCluster, error) {
	log.Debug("get pod cluster starting")
	vInfo := k.k8sInfo["*version.Info"][0]
	vJson, vErr := simplejson.NewJson([]byte(vInfo))
	if vErr != nil {
		log.Errorf("pod cluster initialization version json error: (%s)", vErr.Error())
		return model.PodCluster{}, vErr
	}
	k.podClusterLcuuid = common.GetUUID(k.UuidGenerate, uuid.Nil)
	podCluster := model.PodCluster{
		Lcuuid:       k.podClusterLcuuid,
		Version:      K8S_VERSION_PREFIX + " " + vJson.Get("gitVersion").MustString(),
		Name:         k.Name,
		VPCLcuuid:    k.VPCUUID,
		AZLcuuid:     k.azLcuuid,
		RegionLcuuid: k.RegionUUID,
	}
	log.Debug("get pod cluster complete")
	return podCluster, nil
}
