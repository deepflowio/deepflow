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

package aws

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	uuid "github.com/satori/go.uuid"
)

func (a *Aws) getNatGateways(region awsRegion) ([]model.NATGateway, []model.VInterface, []model.IP, error) {
	log.Debug("get nat gateways starting")
	var natGateways []model.NATGateway
	var natVinterfaces []model.VInterface
	var natIPs []model.IP

	var retNatGateways []types.NatGateway
	var nextToken string
	var maxResults int32 = 100
	for {
		var input *ec2.DescribeNatGatewaysInput
		if nextToken == "" {
			input = &ec2.DescribeNatGatewaysInput{MaxResults: &maxResults}
		} else {
			input = &ec2.DescribeNatGatewaysInput{MaxResults: &maxResults, NextToken: &nextToken}
		}
		result, err := a.ec2Client.DescribeNatGateways(context.TODO(), input)
		if err != nil {
			log.Errorf("nat gateway request aws api error: (%s)", err.Error())
			return []model.NATGateway{}, []model.VInterface{}, []model.IP{}, err
		}
		retNatGateways = append(retNatGateways, result.NatGateways...)
		if result.NextToken == nil {
			break
		}
		nextToken = *result.NextToken
	}

	for _, nData := range retNatGateways {
		natGatewayID := a.getStringPointerValue(nData.NatGatewayId)
		if nData.State != "available" {
			log.Infof("nat gateway (%s) is not available", natGatewayID)
			continue
		}
		floatingIPs := []string{}
		for _, nAddresses := range nData.NatGatewayAddresses {
			if nAddresses.PublicIp != nil {
				floatingIPs = append(floatingIPs, a.getStringPointerValue(nAddresses.PublicIp))
			}
		}
		natGatewayLcuuid := common.GetUUID(natGatewayID, uuid.Nil)
		vpcLcuuid := common.GetUUID(a.getStringPointerValue(nData.VpcId), uuid.Nil)
		natGatewayName := a.getResultTagName(nData.Tags)
		if natGatewayName == "" {
			natGatewayName = natGatewayID
		}
		natGateways = append(natGateways, model.NATGateway{
			Lcuuid:       natGatewayLcuuid,
			Name:         natGatewayName,
			Label:        natGatewayID,
			FloatingIPs:  strings.Join(floatingIPs, ","),
			VPCLcuuid:    vpcLcuuid,
			RegionLcuuid: a.getRegionLcuuid(region.lcuuid),
		})

		vinterfaceLcuuid := common.GetUUID(natGatewayLcuuid, uuid.Nil)
		natVinterfaces = append(natVinterfaces, model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          common.VIF_TYPE_WAN,
			Mac:           common.VIF_DEFAULT_MAC,
			DeviceLcuuid:  natGatewayLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_NAT_GATEWAY,
			NetworkLcuuid: common.NETWORK_ISP_LCUUID,
			VPCLcuuid:     vpcLcuuid,
			RegionLcuuid:  a.getRegionLcuuid(region.lcuuid),
		})

		for _, ip := range floatingIPs {
			natIPs = append(natIPs, model.IP{
				IP:               ip,
				VInterfaceLcuuid: vinterfaceLcuuid,
				SubnetLcuuid:     common.SUBNET_ISP_LCUUID,
				RegionLcuuid:     a.getRegionLcuuid(region.lcuuid),
				Lcuuid:           common.GetUUID(vinterfaceLcuuid+ip, uuid.Nil),
			})
		}
	}
	log.Debug("get nat gateways complete")
	return natGateways, natVinterfaces, natIPs, nil
}
