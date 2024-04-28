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
	"strconv"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (t *Tencent) getRouterAndTables(region tencentRegion) ([]model.VRouter, []model.RoutingTable, error) {
	log.Debug("get routers and tables starting")
	var routers []model.VRouter
	var routerTables []model.RoutingTable
	gwTypeToDesc := map[string]string{
		"HAVIP":          "",
		"DIRECTCONNECT":  "",
		"EIP":            "",
		"CVM":            common.ROUTING_TABLE_TYPE_INSTANCE,
		"VPN":            common.ROUTING_TABLE_TYPE_VPN,
		"PEERCONNECTION": common.ROUTING_TABLE_TYPE_PEER_CONNECTION,
		"NAT":            common.ROUTING_TABLE_TYPE_NAT_GATEWAY,
		"NORMAL_CVM":     common.ROUTING_TABLE_TYPE_INSTANCE,
		"LOCAL_GATEWAY":  common.ROUTING_TABLE_TYPE_LOCAL,
	}

	rAttrs := []string{"RouteTableId", "RouteTableName", "VpcId"}
	rtAttrs := []string{"RouteId", "DestinationCidrBlock", "GatewayType", "GatewayId"}
	rResp, err := t.getResponse("vpc", "2017-03-12", "DescribeRouteTables", region.name, "RouteTableSet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("router request tencent api error: (%s)", err.Error())
		return []model.VRouter{}, []model.RoutingTable{}, err
	}
	for _, rData := range rResp {
		if !t.checkRequiredAttributes(rData, rAttrs) {
			continue
		}
		rID := rData.Get("RouteTableId").MustString()
		rLcuuid := common.GetUUIDByOrgID(t.orgID, rID)
		vpcID := rData.Get("VpcId").MustString()
		routers = append(routers, model.VRouter{
			Lcuuid:       rLcuuid,
			Name:         rData.Get("RouteTableName").MustString(),
			VPCLcuuid:    common.GetUUIDByOrgID(t.orgID, vpcID),
			RegionLcuuid: t.getRegionLcuuid(region.lcuuid),
		})

		routes := rData.Get("RouteSet")
		for r := range routes.MustArray() {
			route := routes.GetIndex(r)
			if !t.checkRequiredAttributes(route, rtAttrs) {
				continue
			}
			routeID := route.Get("RouteId").MustInt()
			destination4 := route.Get("DestinationCidrBlock").MustString()
			destination6 := route.Get("DestinationIpv6CidrBlock").MustString()
			gwID := route.Get("GatewayId").MustString()
			if gwID == "" {
				gwID = common.ROUTING_TABLE_TYPE_LOCAL
			}

			gwTypeDesc := ""
			gwType := route.Get("GatewayType").MustString()
			if gwType != "" {
				gwTypeDesc = gwTypeToDesc[gwType]
				if gwTypeDesc == "" {
					gwTypeDesc = gwType
				}
			}
			if gwTypeDesc == "" {
				gwTypeDesc = common.ROUTING_TABLE_TYPE_LOCAL
			}

			key := rLcuuid + strconv.Itoa(routeID)
			routerTables = append(routerTables, model.RoutingTable{
				Lcuuid:        common.GetUUIDByOrgID(t.orgID, key),
				VRouterLcuuid: rLcuuid,
				Destination:   destination4 + destination6,
				Nexthop:       gwID,
				NexthopType:   gwTypeDesc,
			})
		}
	}
	log.Debug("get routers and tables complete")
	return routers, routerTables, nil
}
