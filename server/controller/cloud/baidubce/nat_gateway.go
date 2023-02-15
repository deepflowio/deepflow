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

package baidubce

import (
	"strings"

	"github.com/baidubce/bce-sdk-go/services/vpc"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (b *BaiduBce) getNatGateways(region model.Region, vpcIdToLcuuid map[string]string) (
	[]model.NATGateway, []model.VInterface, []model.IP, error,
) {
	var retNATGateways []model.NATGateway
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	log.Debug("get nat_gateways starting")

	vpcClient, _ := vpc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	vpcClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	marker := ""
	args := &vpc.ListNatGatewayArgs{}
	results := make([]*vpc.ListNatGatewayResult, 0)
	for {
		args.Marker = marker
		result, err := vpcClient.ListNatGateway(args)
		if err != nil {
			log.Error(err)
			return nil, nil, nil, err
		}
		results = append(results, result)
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}

	b.debugger.WriteJson("ListNatGateway", " ", structToJson(results))
	for _, r := range results {
		for _, nat := range r.Nats {
			vpcLcuuid, ok := vpcIdToLcuuid[nat.VpcId]
			if !ok {
				log.Debugf("nat_gateway (%s) vpc (%s) not found", nat.Id, nat.VpcId)
				continue
			}
			natGatewayLcuuid := common.GenerateUUID(nat.Id)
			retNATGateway := model.NATGateway{
				Lcuuid:       natGatewayLcuuid,
				Name:         nat.Name,
				Label:        nat.Id,
				FloatingIPs:  strings.Join(nat.Eips, ","),
				VPCLcuuid:    vpcLcuuid,
				RegionLcuuid: region.Lcuuid,
			}
			retNATGateways = append(retNATGateways, retNATGateway)
			b.regionLcuuidToResourceNum[retNATGateway.RegionLcuuid]++

			// TODO: 目前Go sdk只能返回snat_ip，需要后续跟进dnat_ips
			// 将nat_ip作为接口 + 公网IP返回
			for _, ip := range nat.Eips {
				vinterfaceLcuuid := common.GenerateUUID(natGatewayLcuuid + ip)
				retVInterface := model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Type:          common.VIF_TYPE_LAN,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceType:    common.VIF_DEVICE_TYPE_NAT_GATEWAY,
					DeviceLcuuid:  natGatewayLcuuid,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  region.Lcuuid,
				}
				retVInterfaces = append(retVInterfaces, retVInterface)

				retIP := model.IP{
					Lcuuid:           common.GenerateUUID(vinterfaceLcuuid + ip),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               ip,
					SubnetLcuuid:     common.NETWORK_ISP_LCUUID,
					RegionLcuuid:     region.Lcuuid,
				}
				retIPs = append(retIPs, retIP)
			}
		}
	}
	log.Debug("get nat_gateways complete")
	return retNATGateways, retVInterfaces, retIPs, nil
}
