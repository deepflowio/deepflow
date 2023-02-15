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

package synchronize

import (
	api "github.com/deepflowio/deepflow/message/trident"
	context "golang.org/x/net/context"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/trisolaris"
)

type KubernetesClusterIDEvent struct {
}

func NewKubernetesClusterIDEvent() *KubernetesClusterIDEvent {
	return &KubernetesClusterIDEvent{}
}

func (k *KubernetesClusterIDEvent) GetKubernetesClusterID(ctx context.Context, in *api.KubernetesClusterIDRequest) (*api.KubernetesClusterIDResponse, error) {
	remote := getRemote(ctx)
	log.Infof("call me from ip: %s to get kubernetes cluster_id", remote)
	log.Debugf("ca_md5: %#v", in.GetCaMd5())

	clusterID, err := common.GenerateKuberneteClusterIDByMD5(in.GetCaMd5())
	if err != nil {
		errorMsg := err.Error()
		return &api.KubernetesClusterIDResponse{ErrorMsg: &errorMsg}, nil
	}

	// cache clusterID & create kubernetes domain
	kubernetesInfo := trisolaris.GetGKubernetesInfo()
	kubernetesInfo.CacheClusterID(clusterID, in.GetKubernetesClusterName())

	log.Infof("response kubernetes cluster_id: %s to ip: %s", clusterID, remote)
	log.Debugf("ca_md5: %#v", in.GetCaMd5())
	return &api.KubernetesClusterIDResponse{ClusterId: &clusterID}, nil
}
