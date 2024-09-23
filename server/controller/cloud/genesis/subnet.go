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

package genesis

import (
	"time"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (g *Genesis) getSubnets() ([]model.Subnet, error) {
	log.Debug("get subnets starting", logger.NewORGPrefix(g.orgID))
	subnets := []model.Subnet{}

	g.cloudStatsd.RefreshAPIMoniter("subnets", len(g.subnets), time.Time{})

	for _, s := range g.subnets {
		if s.NetworkLcuuid == "" {
			log.Debug("network lcuuid not found", logger.NewORGPrefix(g.orgID))
			continue
		}
		subnetName := s.Name
		if subnetName == "" {
			subnetName = "subnet_" + s.Lcuuid[:11]
		}
		subnet := model.Subnet{
			Lcuuid:        s.Lcuuid,
			Name:          subnetName,
			CIDR:          s.CIDR,
			VPCLcuuid:     s.VPCLcuuid,
			NetworkLcuuid: s.NetworkLcuuid,
		}
		subnets = append(subnets, subnet)
	}
	log.Debug("get subnets complete", logger.NewORGPrefix(g.orgID))
	return subnets, nil
}
