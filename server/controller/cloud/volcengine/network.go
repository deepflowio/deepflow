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

package volcengine

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

func (v *VolcEngine) getNetworks(sess *session.Session) ([]model.Network, []model.Subnet, error) {
	log.Debug("get networks starting", logger.NewORGPrefix(v.orgID))
	var networks []model.Network
	var subnets []model.Subnet

	var retSubnets []*vpc.SubnetForDescribeSubnetsOutput
	var nextToken *string
	var maxResults int64 = 100
	for {
		input := &vpc.DescribeSubnetsInput{MaxResults: &maxResults, NextToken: nextToken}
		result, err := vpc.New(sess).DescribeSubnets(input)
		if err != nil {
			log.Errorf("request volcengine (vpc.DescribeSubnets) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.Network{}, []model.Subnet{}, err
		}
		retSubnets = append(retSubnets, result.Subnets...)
		if v.getStringPointerValue(result.NextToken) == "" {
			break
		}
		nextToken = result.NextToken
	}

	for _, subnet := range retSubnets {
		if subnet == nil {
			continue
		}
		vpcID := v.getStringPointerValue(subnet.VpcId)
		subnetID := v.getStringPointerValue(subnet.SubnetId)
		subnetName := v.getStringPointerValue(subnet.SubnetName)
		networkLcuuid := common.GetUUIDByOrgID(v.orgID, subnetID)
		vpcLcuuid := common.GetUUIDByOrgID(v.orgID, vpcID)
		azLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(subnet.ZoneId))

		networks = append(networks, model.Network{
			Lcuuid:         networkLcuuid,
			Name:           subnetName,
			SegmentationID: 1,
			VPCLcuuid:      vpcLcuuid,
			Shared:         false,
			External:       false,
			NetType:        common.NETWORK_TYPE_LAN,
			AZLcuuid:       azLcuuid,
			RegionLcuuid:   v.regionLcuuid,
		})
		v.azLcuuids[azLcuuid] = false

		// ipv6 is not fully supported of volcengine
		subnets = append(subnets, model.Subnet{
			Lcuuid:        common.GetUUIDByOrgID(v.orgID, networkLcuuid),
			Name:          subnetName,
			CIDR:          v.getStringPointerValue(subnet.CidrBlock),
			VPCLcuuid:     vpcLcuuid,
			NetworkLcuuid: networkLcuuid,
		})
	}
	log.Debug("get networks complete", logger.NewORGPrefix(v.orgID))
	return networks, subnets, nil
}
