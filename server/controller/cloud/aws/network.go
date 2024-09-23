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

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (a *Aws) getNetworks(client *ec2.Client) ([]model.Network, []model.Subnet, []model.VInterface, error) {
	log.Debug("get networks starting", logger.NewORGPrefix(a.orgID))
	var networks []model.Network
	var subnets []model.Subnet
	var netVinterfaces []model.VInterface

	var retNetworks []types.Subnet
	var nextToken string
	var maxResults int32 = 100
	for {
		var input *ec2.DescribeSubnetsInput
		if nextToken == "" {
			input = &ec2.DescribeSubnetsInput{MaxResults: &maxResults}
		} else {
			input = &ec2.DescribeSubnetsInput{MaxResults: &maxResults, NextToken: &nextToken}
		}
		result, err := client.DescribeSubnets(context.TODO(), input)
		if err != nil {
			log.Errorf("network request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
			return []model.Network{}, []model.Subnet{}, []model.VInterface{}, err
		}
		retNetworks = append(retNetworks, result.Subnets...)
		if result.NextToken == nil {
			break
		}
		nextToken = *result.NextToken
	}

	for _, nData := range retNetworks {
		networkVpcID := a.getStringPointerValue(nData.VpcId)
		networkSubnetID := a.getStringPointerValue(nData.SubnetId)
		networkLcuuid := common.GetUUIDByOrgID(a.orgID, networkSubnetID)
		vpcLcuuid := common.GetUUIDByOrgID(a.orgID, networkVpcID)
		azLcuuid := common.GetUUIDByOrgID(a.orgID, a.getStringPointerValue(nData.AvailabilityZone))
		networkName := a.getResultTagName(nData.Tags)
		if networkName == "" {
			networkName = networkSubnetID
		}
		networks = append(networks, model.Network{
			Lcuuid:         networkLcuuid,
			Name:           networkName,
			SegmentationID: 1,
			VPCLcuuid:      vpcLcuuid,
			Shared:         false,
			External:       false,
			NetType:        common.NETWORK_TYPE_LAN,
			AZLcuuid:       azLcuuid,
			RegionLcuuid:   a.regionLcuuid,
		})
		a.azLcuuidMap[azLcuuid] = 0

		subnets = append(subnets, model.Subnet{
			Lcuuid:        common.GetUUIDByOrgID(a.orgID, networkLcuuid),
			Name:          networkName,
			CIDR:          a.getStringPointerValue(nData.CidrBlock),
			VPCLcuuid:     vpcLcuuid,
			NetworkLcuuid: networkLcuuid,
		})

		routerID, ok := a.vpcOrSubnetToRouter[networkSubnetID]
		if !ok {
			routerID = a.vpcOrSubnetToRouter[networkVpcID]
		}
		if routerID != "" {
			netVinterfaces = append(netVinterfaces, model.VInterface{
				Lcuuid:        common.GetUUIDByOrgID(a.orgID, networkSubnetID+routerID),
				Type:          common.VIF_TYPE_LAN,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceLcuuid:  common.GetUUIDByOrgID(a.orgID, routerID),
				DeviceType:    common.VIF_DEVICE_TYPE_VROUTER,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  a.regionLcuuid,
			})
		}
	}
	log.Debug("get networks complete", logger.NewORGPrefix(a.orgID))
	return networks, subnets, netVinterfaces, nil
}
