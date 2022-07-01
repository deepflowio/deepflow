package baidubce

import (
	"github.com/baidubce/bce-sdk-go/services/vpc"

	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
)

func (b *BaiduBce) getRouterAndTables(
	region model.Region, vpcIdToLcuuid map[string]string, vpcIdToName map[string]string,
) ([]model.VRouter, []model.RoutingTable, error) {
	var retVRouters []model.VRouter
	var retRoutingTables []model.RoutingTable

	log.Debug("get routers starting")

	// 每个VPC下一个路由表，抽象为路由器
	vpcClient, _ := vpc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	for vpcId, vpcLcuuid := range vpcIdToLcuuid {
		result, err := vpcClient.GetRouteTableDetail("", vpcId)
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}

		vrouterLcuuid := common.GenerateUUID(result.RouteTableId)
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
			tableLcuuid := common.GenerateUUID(vrouterLcuuid + destination + nexthop)
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
