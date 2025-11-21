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
	"strconv"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (k *KubernetesGather) getPodExposedServices() ([]model.PodService, []model.PodServicePort, error) {
	log.Debug("get exposed ports starting", logger.NewORGPrefix(k.orgID))
	var services []model.PodService
	var servicePorts []model.PodServicePort
	exposedPorts, err := common.ParseRangePorts(k.PodExposedPorts)
	if err != nil {
		log.Errorf("parse pod exposed ports (%s) failed: %s", k.PodExposedPorts, err.Error(), logger.NewORGPrefix(k.orgID))
		return []model.PodService{}, []model.PodServicePort{}, err
	}
	for _, exposedPort := range exposedPorts {
		svcKey := k.Name + ":" + strconv.Itoa(exposedPort)
		svcLcuuid := common.GetUUIDByOrgID(k.orgID, svcKey)
		services = append(services, model.PodService{
			Lcuuid:             svcLcuuid,
			Name:               svcKey,
			Type:               common.POD_SERVICE_TYPE_NODEPORT,
			PodNamespaceLcuuid: common.DEFAULT_POD_NAMESPACE,
			VPCLcuuid:          k.VPCUUID,
			AZLcuuid:           k.azLcuuid,
			RegionLcuuid:       k.RegionUUID,
			PodClusterLcuuid:   k.podClusterLcuuid,
		})
		protocol := "TCP"
		servicePorts = append(servicePorts, model.PodServicePort{
			Lcuuid:           common.GetUUIDByOrgID(k.orgID, svcKey+protocol),
			Protocol:         protocol,
			Port:             exposedPort,
			TargetPort:       exposedPort,
			NodePort:         exposedPort,
			PodServiceLcuuid: svcLcuuid,
		})
	}
	log.Debug("get exposed ports complete", logger.NewORGPrefix(k.orgID))
	return services, servicePorts, nil
}
