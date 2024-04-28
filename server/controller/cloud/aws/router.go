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
)

func (a *Aws) getRouterAndTables(region awsRegion) ([]model.VRouter, []model.RoutingTable, error) {
	log.Debug("get routers and tables starting")
	a.vpcOrSubnetToRouter = map[string]string{}
	var routers []model.VRouter
	var routerTables []model.RoutingTable
	nextHopTypes := map[string]string{
		"i-":    "Instance",
		"eni-":  "Network Interface",
		"vgw-":  "Virtual Private Gateway",
		"eigw-": "Egress Only Internat Gateway",
		"igw-":  common.ROUTING_TABLE_TYPE_NAT_GATEWAY,
		"nat-":  common.ROUTING_TABLE_TYPE_NAT_GATEWAY,
		"pcx-":  common.ROUTING_TABLE_TYPE_PEER_CONNECTION,
	}

	var retRouteTables []types.RouteTable
	var nextToken string
	var maxResults int32 = 100
	for {
		var input *ec2.DescribeRouteTablesInput
		if nextToken == "" {
			input = &ec2.DescribeRouteTablesInput{MaxResults: &maxResults}
		} else {
			input = &ec2.DescribeRouteTablesInput{MaxResults: &maxResults, NextToken: &nextToken}
		}
		result, err := a.ec2Client.DescribeRouteTables(context.TODO(), input)
		if err != nil {
			log.Errorf("routetable request aws api error: (%s)", err.Error())
			return []model.VRouter{}, []model.RoutingTable{}, err
		}
		retRouteTables = append(retRouteTables, result.RouteTables...)
		if result.NextToken == nil {
			break
		}
		nextToken = *result.NextToken
	}

	for _, rData := range retRouteTables {
		routeTableID := a.getStringPointerValue(rData.RouteTableId)
		routeTableLcuuid := common.GetUUIDByOrgID(a.orgID, routeTableID)
		routeTableName := a.getResultTagName(rData.Tags)
		if routeTableName == "" {
			routeTableName = routeTableID
		}
		vpcID := a.getStringPointerValue(rData.VpcId)
		for _, association := range rData.Associations {
			if association.SubnetId != nil {
				a.vpcOrSubnetToRouter[a.getStringPointerValue(association.SubnetId)] = a.getStringPointerValue(association.RouteTableId)
			} else if a.getBoolPointerValue(association.Main) {
				a.vpcOrSubnetToRouter[vpcID] = a.getStringPointerValue(association.RouteTableId)
			}
		}
		routers = append(routers, model.VRouter{
			Lcuuid:       routeTableLcuuid,
			Name:         routeTableName,
			VPCLcuuid:    common.GetUUIDByOrgID(a.orgID, vpcID),
			RegionLcuuid: a.getRegionLcuuid(region.lcuuid),
		})

		for _, route := range rData.Routes {
			if route.State != "active" {
				continue
			}
			var gatewayID string
			switch {
			case route.VpcPeeringConnectionId != nil:
				gatewayID = *route.VpcPeeringConnectionId
			case route.NetworkInterfaceId != nil:
				gatewayID = *route.NetworkInterfaceId
			case route.NatGatewayId != nil:
				gatewayID = *route.NatGatewayId
			case route.GatewayId != nil:
				gatewayID = *route.GatewayId
			case route.InstanceId != nil:
				gatewayID = *route.InstanceId
			default:
				log.Infof("routetable rule (%s) gateway id not found", route)
				continue
			}
			prefix := gatewayID[:strings.Index(gatewayID, "-")+1]
			var nextHopType string
			if nType, ok := nextHopTypes[prefix]; ok {
				nextHopType = nType
			} else {
				nextHopType = common.ROUTING_TABLE_TYPE_LOCAL
			}
			destination := a.getStringPointerValue(route.DestinationCidrBlock) + a.getStringPointerValue(route.DestinationIpv6CidrBlock)
			routerTables = append(routerTables, model.RoutingTable{
				Lcuuid:        common.GetUUIDByOrgID(a.orgID, routeTableLcuuid+destination+gatewayID),
				VRouterLcuuid: routeTableLcuuid,
				Destination:   destination,
				Nexthop:       gatewayID,
				NexthopType:   nextHopType,
			})
		}
	}
	log.Debug("get routers and tables complete")
	return routers, routerTables, nil
}
