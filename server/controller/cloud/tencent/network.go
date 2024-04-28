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

package tencent

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (t *Tencent) getNetworks(region tencentRegion) ([]model.Network, []model.Subnet, []model.VInterface, error) {
	log.Debug("get networks starting")
	var networks []model.Network
	var subnets []model.Subnet
	var netVinterfaces []model.VInterface

	attrs := []string{"SubnetId", "SubnetName", "VpcId", "CidrBlock"}
	resp, err := t.getResponse("vpc", "2017-03-12", "DescribeSubnets", region.name, "SubnetSet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("network request tencent api error: (%s)", err.Error())
		return []model.Network{}, []model.Subnet{}, []model.VInterface{}, err
	}
	for _, nData := range resp {
		if !t.checkRequiredAttributes(nData, attrs) {
			continue
		}
		vpcID := nData.Get("VpcId").MustString()
		subnetID := nData.Get("SubnetId").MustString()
		azID := nData.Get("Zone").MustString()
		networkLcuuid := common.GetUUIDByOrgID(t.orgID, subnetID)
		vpcLcuuid := common.GetUUIDByOrgID(t.orgID, vpcID)
		azLcuuid := common.GetUUIDByOrgID(t.orgID, t.uuidGenerate+"_"+azID)
		networkName := nData.Get("SubnetName").MustString()
		networks = append(networks, model.Network{
			Lcuuid:         networkLcuuid,
			Name:           networkName,
			SegmentationID: 1,
			VPCLcuuid:      vpcLcuuid,
			Shared:         false,
			External:       false,
			NetType:        common.NETWORK_TYPE_LAN,
			AZLcuuid:       azLcuuid,
			RegionLcuuid:   t.getRegionLcuuid(region.lcuuid),
		})
		t.azLcuuidMap[azLcuuid] = 0

		cidr4 := nData.Get("CidrBlock").MustString()
		cidr6 := nData.Get("Ipv6CidrBlock").MustString()
		subnets = append(subnets, model.Subnet{
			Lcuuid:        common.GetUUIDByOrgID(t.orgID, networkLcuuid),
			Name:          networkName,
			CIDR:          cidr4 + cidr6,
			NetworkLcuuid: networkLcuuid,
			VPCLcuuid:     vpcLcuuid,
		})

		routeTableID := nData.Get("RouteTableId").MustString()
		if routeTableID != "" {
			netVinterfaces = append(netVinterfaces, model.VInterface{
				Lcuuid:        common.GetUUIDByOrgID(t.orgID, subnetID+routeTableID),
				Type:          common.VIF_TYPE_LAN,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceLcuuid:  common.GetUUIDByOrgID(t.orgID, routeTableID),
				DeviceType:    common.VIF_DEVICE_TYPE_VROUTER,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  t.getRegionLcuuid(region.lcuuid),
			})
		}
	}
	log.Debug("get networks complete")
	return networks, subnets, netVinterfaces, nil
}
