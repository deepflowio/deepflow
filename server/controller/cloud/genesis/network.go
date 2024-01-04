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
	"strconv"
	"time"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"

	uuid "github.com/satori/go.uuid"
)

func (g *Genesis) getNetworks() ([]model.Network, error) {
	log.Debug("get networks starting")
	networks := []model.Network{}
	networksData := g.genesisData.Networks

	g.cloudStatsd.RefreshAPIMoniter("networks", len(networksData), time.Time{})

	for _, n := range networksData {
		if n.SegmentationID == 0 {
			log.Debug("segmentation id not found")
			continue
		}
		vpcLcuuid := n.VPCLcuuid
		if vpcLcuuid == "" {
			vpcLcuuid = common.GetUUID(g.defaultVpcName, uuid.Nil)
			g.defaultVpc = true
		}
		networkName := n.Name
		if networkName == "" {
			networkName = "subnet_vni_" + strconv.Itoa(int(n.SegmentationID))
		}
		network := model.Network{
			Lcuuid:         n.Lcuuid,
			Name:           networkName,
			SegmentationID: int(n.SegmentationID),
			VPCLcuuid:      vpcLcuuid,
			Shared:         false,
			External:       n.External,
			NetType:        int(n.NetType),
			AZLcuuid:       g.azLcuuid,
			RegionLcuuid:   g.regionUuid,
		}
		networks = append(networks, network)
	}
	log.Debug("get networks complete")
	return networks, nil
}
