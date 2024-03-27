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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (t *Tencent) getNatGateways(region tencentRegion) ([]model.NATGateway, []model.VInterface, []model.IP, error) {
	log.Debug("get nat gateways starting")
	var natGateways []model.NATGateway
	var natVinterfaces []model.VInterface
	var natIPs []model.IP

	attrs := []string{"NatGatewayId", "NatGatewayName", "VpcId"}

	resp, err := t.getResponse("vpc", "2017-03-12", "DescribeNatGateways", region.name, "NatGatewaySet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("nat gateway request tencent api error: (%s)", err.Error())
		return []model.NATGateway{}, []model.VInterface{}, []model.IP{}, err
	}
	for _, nData := range resp {
		if !t.checkRequiredAttributes(nData, attrs) {
			continue
		}
		natID := nData.Get("NatGatewayId").MustString()
		natLcuuid := common.GenerateUUID(natID)
		vpcLcuuid := common.GenerateUUID(nData.Get("VpcId").MustString())
		floatingIPs := []string{}
		for i := range nData.Get("PublicIpAddressSet").MustArray() {
			floatingIPs = append(floatingIPs, nData.Get("PublicIpAddressSet").GetIndex(i).Get("PublicIpAddress").MustString())
		}
		natGateways = append(natGateways, model.NATGateway{
			Lcuuid:       natLcuuid,
			Name:         nData.Get("NatGatewayName").MustString(),
			Label:        natID,
			FloatingIPs:  strings.Join(floatingIPs, ","),
			VPCLcuuid:    vpcLcuuid,
			RegionLcuuid: t.getRegionLcuuid(region.lcuuid),
		})
		t.natIDs = append(t.natIDs, natID)

		if len(floatingIPs) > 0 {
			vinterfaceLcuuid := common.GenerateUUID(natLcuuid)
			natVinterfaces = append(natVinterfaces, model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          common.VIF_TYPE_WAN,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceLcuuid:  natLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_NAT_GATEWAY,
				NetworkLcuuid: common.NETWORK_ISP_LCUUID,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  t.getRegionLcuuid(region.lcuuid),
			})
			for _, ip := range floatingIPs {
				natIPs = append(natIPs, model.IP{
					Lcuuid:           common.GenerateUUID(vinterfaceLcuuid + ip),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               ip,
					RegionLcuuid:     t.getRegionLcuuid(region.lcuuid),
				})
			}
		}
	}
	log.Debug("get nat gateways complete")
	return natGateways, natVinterfaces, natIPs, nil
}
