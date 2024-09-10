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

package aliyun

import (
	vpc "github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (a *Aliyun) getRouterAndTables(region model.Region) ([]model.VRouter, []model.RoutingTable) {
	var retVRouters []model.VRouter
	var retRoutingTables []model.RoutingTable

	log.Debug("get routers starting", logger.NewORGPrefix(a.orgID))
	request := vpc.CreateDescribeRouteTableListRequest()
	response, err := a.getRouterResponse(region.Label, request)
	if err != nil {
		log.Warning(err, logger.NewORGPrefix(a.orgID))
		return []model.VRouter{}, []model.RoutingTable{}
	}

	for _, r := range response {
		instances, _ := r.Get("RouterTableListType").Array()
		for i := range instances {
			router := r.Get("RouterTableListType").GetIndex(i)

			err := a.checkRequiredAttributes(router, []string{"RouteTableId", "VpcId"})
			if err != nil {
				continue
			}

			routerTableId := router.Get("RouteTableId").MustString()
			routerTableName := router.Get("RouteTableName").MustString()
			if routerTableName == "" {
				routerTableName = routerTableId
			}
			vpcId := router.Get("VpcId").MustString()

			routerLcuuid := common.GenerateUUIDByOrgID(a.orgID, routerTableId)
			retVRouter := model.VRouter{
				Lcuuid:       routerLcuuid,
				Name:         routerTableName,
				VPCLcuuid:    common.GenerateUUIDByOrgID(a.orgID, vpcId),
				RegionLcuuid: a.regionLcuuid,
			}
			retVRouters = append(retVRouters, retVRouter)

			// 路由表规则
			retRoutingTables = append(retRoutingTables, a.getRouterTables(region, routerTableId)...)

		}
	}

	log.Debug("get routers complete", logger.NewORGPrefix(a.orgID))
	return retVRouters, retRoutingTables
}

func (a *Aliyun) getRouterTables(region model.Region, routerId string) []model.RoutingTable {
	var retRoutingTables []model.RoutingTable

	request := vpc.CreateDescribeRouteEntryListRequest()
	request.RouteTableId = routerId
	response, err := a.getRouterTableResponse(region.Label, request)
	if err != nil {
		log.Warning(err, logger.NewORGPrefix(a.orgID))
		return []model.RoutingTable{}
	}

	routerLcuuid := common.GenerateUUIDByOrgID(a.orgID, routerId)
	for _, rRule := range response {
		for j := range rRule.Get("RouteEntry").MustArray() {
			rule := rRule.Get("RouteEntry").GetIndex(j)
			err := a.checkRequiredAttributes(
				rule, []string{"RouteEntryId", "Status", "DestinationCidrBlock"},
			)
			if err != nil {
				continue
			}

			status := rule.Get("Status").MustString()
			if status != "Available" {
				continue
			}

			ruleId := rule.Get("RouteEntryId").MustString()
			destination := rule.Get("DestinationCidrBlock").MustString()
			nexthops := rule.Get("NextHops").Get("NextHop")

			if len(nexthops.MustArray()) == 0 {
				log.Infof("route table (%s) gateway id not found", ruleId, logger.NewORGPrefix(a.orgID))
				continue
			}
			nexthop := common.ROUTING_TABLE_TYPE_LOCAL
			nexthopType := common.ROUTING_TABLE_TYPE_LOCAL
			n := nexthops.GetIndex(0)
			nexthopId := n.Get("NextHopId").MustString()
			if nexthopId != "" {
				nexthop = nexthopId
			}
			nType := n.Get("NextHopType").MustString()
			if nType != "" {
				nexthopType = nType
			}
			if nexthopType == "NatGateway" {
				nexthopType = common.ROUTING_TABLE_TYPE_NAT_GATEWAY
			}

			retRule := model.RoutingTable{
				Lcuuid:        common.GenerateUUIDByOrgID(a.orgID, routerLcuuid+destination+nexthop),
				VRouterLcuuid: routerLcuuid,
				Destination:   destination,
				NexthopType:   nexthopType,
				Nexthop:       nexthop,
			}
			retRoutingTables = append(retRoutingTables, retRule)
		}
	}

	return retRoutingTables
}
