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
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/genesis"
)

func (k *KubernetesGather) getPrometheusTargets() ([]model.PrometheusTarget, error) {
	log.Debug("get prometheus target starting")
	var prometheusTargets []model.PrometheusTarget
	pTargets, err := genesis.GenesisService.GetPrometheusResponse(k.ClusterID)
	if err != nil {
		log.Warning(err.Error())
		return prometheusTargets, err
	}
	for _, p := range pTargets {
		var otherLabelsString string
		if !p.HonorLabelsConfig {
			otherLabelsString = p.OtherLabels
		}
		prometheusTargets = append(prometheusTargets, cloudmodel.PrometheusTarget{
			Lcuuid:           common.GetUUIDByOrgID(k.orgID, k.ClusterID+p.Instance+p.Job+otherLabelsString),
			Job:              p.Job,
			Instance:         p.Instance,
			ScrapeURL:        p.ScrapeURL,
			OtherLabels:      otherLabelsString,
			PodClusterLcuuid: k.podClusterLcuuid,
			VPCLcuuid:        k.VPCUUID,
		})
	}
	log.Debug("get prometheus target complete")
	return prometheusTargets, nil
}
