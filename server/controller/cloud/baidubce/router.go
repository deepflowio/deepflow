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

package baidubce

import (
	"time"

	"github.com/baidubce/bce-sdk-go/services/vpc"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (b *BaiduBce) getRouterAndTables(
	region model.Region, vpcIdToLcuuid map[string]string, vpcIdToName map[string]string,
) ([]model.VRouter, []model.RoutingTable, error) {
	var retVRouters []model.VRouter
	var retRoutingTables []model.RoutingTable

	log.Debug("get routers starting")

	// 每个VPC下一个路由表，抽象为路由器
	vpcClient, _ := vpc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	vpcClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	for vpcId, vpcLcuuid := range vpcIdToLcuuid {
		startTime := time.Now()
		result, err := vpcClient.GetRouteTableDetail("", vpcId)
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}

		b.cloudStatsd.RefreshAPIMoniter("GetRouteTableDetail", len(result.RouteRules), startTime)
		b.debugger.WriteJson("GetRouteTableDetail", " ", structToJson([]*vpc.GetRouteTableResult{result}))
		vrouterLcuuid := common.GenerateUUIDByOrgID(b.orgID, result.RouteTableId)
		vrouterName, _ := vpcIdToName[vpcId]
		retVRouter := model.VRouter{
			Lcuuid:       vrouterLcuuid,
			Name:         vrouterName,
			VPCLcuuid:    vpcLcuuid,
			RegionLcuuid: region.Lcuuid,
		}
		retVRouters = append(retVRouters, retVRouter)
		b.regionLcuuidToResourceNum[retVRouter.RegionLcuuid]++

		// 暂不支持对接连接专线网关的路由表(无法创建可用的专线网关)
		nexthop_types := map[string]string{
			"peerConn": common.ROUTING_TABLE_TYPE_PEER_CONNECTION,
			"nat":      common.ROUTING_TABLE_TYPE_NAT_GATEWAY,
			"vpn":      common.ROUTING_TABLE_TYPE_VPN,
			"custom":   common.ROUTING_TABLE_TYPE_INSTANCE,
			"local":    common.ROUTING_TABLE_TYPE_LOCAL,
			"sys":      common.ROUTING_TABLE_TYPE_LOCAL,
		}
		for _, rule := range result.RouteRules {
			destination := rule.DestinationAddress
			if destination == "" {
				log.Debugf("no destination_address in rule (%d)", rule.RouteRuleId)
				continue
			}
			nexthop := rule.NexthopId
			if nexthop == "" {
				nexthop = common.ROUTING_TABLE_TYPE_LOCAL
			}
			nexthopType := common.ROUTING_TABLE_TYPE_LOCAL
			if nType, ok := nexthop_types[string(rule.NexthopType)]; ok {
				nexthopType = nType
			}
			tableLcuuid := common.GenerateUUIDByOrgID(b.orgID, vrouterLcuuid+destination+nexthop)
			retRoutingTable := model.RoutingTable{
				Lcuuid:        tableLcuuid,
				VRouterLcuuid: vrouterLcuuid,
				Destination:   destination,
				NexthopType:   nexthopType,
				Nexthop:       nexthop,
			}
			retRoutingTables = append(retRoutingTables, retRoutingTable)
		}
	}
	log.Debug("get routers complete")
	return retVRouters, retRoutingTables, nil
}
