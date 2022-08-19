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

package tencent

import (
	"strings"

	"github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/satori/go.uuid"
)

func (t *Tencent) getNatGateways(region tencentRegion) ([]model.NATGateway, []model.VInterface, []model.IP, error) {
	log.Debug("get nat gateways starting")
	var natGateways []model.NATGateway
	var natVinterfaces []model.VInterface
	var natIPs []model.IP

	attrs := []string{"NatId", "NatName", "VpcId"}

	if _, ok := natGatewaySupportRegion[region.name]; !ok {
		log.Debugf("nat gateway api unsupported region: (%s)", region.name)
		return []model.NATGateway{}, []model.VInterface{}, []model.IP{}, nil
	}

	resp, err := t.getResponse("bmvpc", "2018-06-25", "DescribeNatGateways", region.name, "NatGatewayInfoSet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("nat gateway request tencent api error: (%s)", err.Error())
		return []model.NATGateway{}, []model.VInterface{}, []model.IP{}, nil
	}
	for _, nData := range resp {
		if !t.checkRequiredAttributes(nData, attrs) {
			continue
		}
		natID := nData.Get("NatId").MustString()
		natLcuuid := common.GetUUID(natID, uuid.Nil)
		vpcLcuuid := common.GetUUID(nData.Get("VpcId").MustString(), uuid.Nil)
		floatingIPs := []string{}
		for i := range nData.Get("Eips").MustArray() {
			floatingIPs = append(floatingIPs, nData.Get("Eips").GetIndex(i).MustString())
		}
		natGateways = append(natGateways, model.NATGateway{
			Lcuuid:       natLcuuid,
			Name:         nData.Get("NatName").MustString(),
			Label:        natID,
			FloatingIPs:  strings.Join(floatingIPs, ","),
			VPCLcuuid:    vpcLcuuid,
			RegionLcuuid: region.lcuuid,
		})
		t.natIDs = append(t.natIDs, natID)

		if len(floatingIPs) > 0 {
			vinterfaceLcuuid := common.GetUUID(natLcuuid, uuid.Nil)
			natVinterfaces = append(natVinterfaces, model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          common.VIF_TYPE_WAN,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceLcuuid:  natLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_NAT_GATEWAY,
				NetworkLcuuid: common.NETWORK_ISP_LCUUID,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  region.lcuuid,
			})
			for _, ip := range floatingIPs {
				natIPs = append(natIPs, model.IP{
					Lcuuid:           common.GetUUID(vinterfaceLcuuid+ip, uuid.Nil),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               ip,
					SubnetLcuuid:     common.NETWORK_ISP_LCUUID,
					RegionLcuuid:     region.lcuuid,
				})
			}
		}
	}
	log.Debug("get nat gateways complete")
	return natGateways, natVinterfaces, natIPs, nil
}
