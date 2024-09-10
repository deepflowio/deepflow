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

package aws

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (a *Aws) getNatGateways(client *ec2.Client) ([]model.NATGateway, []model.VInterface, []model.IP, error) {
	log.Debug("get nat gateways starting", logger.NewORGPrefix(a.orgID))
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
		result, err := client.DescribeNatGateways(context.TODO(), input)
		if err != nil {
			log.Errorf("nat gateway request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
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
			log.Infof("nat gateway (%s) is not available", natGatewayID, logger.NewORGPrefix(a.orgID))
			continue
		}
		floatingIPs := []string{}
		for _, nAddresses := range nData.NatGatewayAddresses {
			if nAddresses.PublicIp != nil {
				floatingIPs = append(floatingIPs, a.getStringPointerValue(nAddresses.PublicIp))
			}
		}
		natGatewayLcuuid := common.GetUUIDByOrgID(a.orgID, natGatewayID)
		vpcLcuuid := common.GetUUIDByOrgID(a.orgID, a.getStringPointerValue(nData.VpcId))
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
			RegionLcuuid: a.regionLcuuid,
		})

		vinterfaceLcuuid := common.GetUUIDByOrgID(a.orgID, natGatewayLcuuid)
		natVinterfaces = append(natVinterfaces, model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          common.VIF_TYPE_WAN,
			Mac:           common.VIF_DEFAULT_MAC,
			DeviceLcuuid:  natGatewayLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_NAT_GATEWAY,
			NetworkLcuuid: common.NETWORK_ISP_LCUUID,
			VPCLcuuid:     vpcLcuuid,
			RegionLcuuid:  a.regionLcuuid,
		})

		for _, ip := range floatingIPs {
			natIPs = append(natIPs, model.IP{
				IP:               ip,
				VInterfaceLcuuid: vinterfaceLcuuid,
				RegionLcuuid:     a.regionLcuuid,
				Lcuuid:           common.GetUUIDByOrgID(a.orgID, vinterfaceLcuuid+ip),
			})
		}
	}
	log.Debug("get nat gateways complete", logger.NewORGPrefix(a.orgID))
	return natGateways, natVinterfaces, natIPs, nil
}
