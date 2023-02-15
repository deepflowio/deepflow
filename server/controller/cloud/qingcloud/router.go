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

package qingcloud

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (q *QingCloud) GetRouterAndTables() (
	[]model.VRouter, []model.RoutingTable, []model.VInterface, []model.IP, error,
) {
	var retVRouters []model.VRouter
	var retRoutingTables []model.RoutingTable
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	log.Info("get routers starting")

	for regionId, regionLcuuid := range q.RegionIdToLcuuid {
		// 获取普通路由表
		kwargs := []*Param{{"zone", regionId}}
		response, err := q.GetResponse("DescribeRouteTables", "routing_table_set", kwargs)
		if err != nil {
			log.Error(err)
			return nil, nil, nil, nil, err
		}

		for _, r := range response {
			for i := range r.MustArray() {
				router := r.GetIndex(i)
				err := q.CheckRequiredAttributes(router, []string{
					"rtable_id", "rtable_name", "resource_map",
				})
				if err != nil {
					continue
				}

				routerId := router.Get("rtable_id").MustString()
				routerName := router.Get("rtable_name").MustString()
				if routerName == "" {
					routerName = routerId
				}

				vxnetId := ""
				for key := range router.Get("resource_map").MustMap() {
					resource := router.Get("resource_map").Get(key)
					resourceType := resource.Get("resource_type").MustString()
					if resourceType == "vxnet" {
						vxnetId = resource.Get("resource_id").MustString()
					} else {
						vxnetId = resource.Get("vxnet").Get("vxnet_id").MustString()
					}
					break
				}
				if vxnetId == "" {
					log.Infof("routing table (%s) vxnetId not found", routerId)
					continue
				}
				vpcLcuuid, ok := q.vxnetIdToVPCLcuuid[vxnetId]
				if !ok {
					log.Infof("routing table (%s) vxnetId (%s) vpc not found", routerId, vxnetId)
					continue
				}

				routerLcuuid := common.GenerateUUID(routerId)
				retVRouters = append(retVRouters, model.VRouter{
					Lcuuid:       routerLcuuid,
					Name:         routerName,
					Label:        routerId,
					VPCLcuuid:    vpcLcuuid,
					RegionLcuuid: regionLcuuid,
				})
				q.regionLcuuidToResourceNum[regionLcuuid]++

				// 获取路由表规则
				for j := range router.Get("routing_table_rule_set").MustArray() {
					routerTable := router.Get("routing_table_rule_set").GetIndex(j)
					err := q.CheckRequiredAttributes(routerTable, []string{
						"rtable_rule_id", "nexthop_type", "network", "nexthop",
					})
					if err != nil {
						continue
					}

					nexthopType := common.ROUTING_TABLE_TYPE_LOCAL
					ruleNexthopType := routerTable.Get("nexthop_type").MustInt()
					if ruleNexthopType == 2 {
						nexthopType = common.ROUTING_TABLE_TYPE_ROUTER
					} else if ruleNexthopType == 4 {
						nexthopType = common.ROUTING_TABLE_TYPE_NAT_GATEWAY
					}

					routerTableId := routerTable.Get("rtable_rule_id").MustString()
					retRoutingTables = append(retRoutingTables, model.RoutingTable{
						Lcuuid:        common.GenerateUUID(routerTableId),
						VRouterLcuuid: routerLcuuid,
						Destination:   routerTable.Get("network").MustString(),
						NexthopType:   nexthopType,
						Nexthop:       routerTable.Get("nexthop").MustString(),
					})
				}
			}
		}
		// 获取边界路由器
		kwargs = []*Param{{"zone", regionId}, {"status.1", "active"}}
		response, err = q.GetResponse("DescribeVpcBorders", "vpc_border_set", kwargs)
		if err != nil {
			log.Error(err)
			return nil, nil, nil, nil, err
		}

		for _, r := range response {
			for i := range r.MustArray() {
				router := r.GetIndex(i)
				err := q.CheckRequiredAttributes(router, []string{
					"border_name", "vpc_border_id", "router_id",
				})
				if err != nil {
					continue
				}

				borderId := router.Get("vpc_border_id").MustString()
				borderName := router.Get("border_name").MustString()
				if borderName == "" {
					borderName = borderId
				}
				routerId := router.Get("router_id").MustString()
				if routerId == "" {
					continue
				}
				routerLcuuid := common.GenerateUUID(borderId)
				vpcLcuuid := common.GenerateUUID(routerId)
				retVRouters = append(retVRouters, model.VRouter{
					Lcuuid:       routerLcuuid,
					Name:         borderName,
					Label:        borderId,
					VPCLcuuid:    vpcLcuuid,
					RegionLcuuid: regionLcuuid,
				})

				// 获取边界路由器的网络信息
				borderNetKwargs := []*Param{{"zone", regionId}, {"border", borderId}}
				borderNetResponse, err := q.GetResponse(
					"DescribeBorderVxnets", "border_vxnet_set", borderNetKwargs,
				)
				if err != nil {
					log.Error(err)
					return nil, nil, nil, nil, err
				}

				vpcNetKwargs := []*Param{{"zone", regionId}, {"router", routerId}}
				vpcNetResponse, err := q.GetResponse(
					"DescribeRouterVxnets", "router_vxnet_set", vpcNetKwargs,
				)
				if err != nil {
					log.Error(err)
					return nil, nil, nil, nil, err
				}

				for _, rNet := range append(borderNetResponse, vpcNetResponse...) {
					for i := range rNet.MustArray() {
						net := rNet.GetIndex(i)
						vxnetId := net.Get("vxnet_id").MustString()
						if vxnetId == "" {
							log.Debugf("border router (%s) not binding network", borderName)
							continue
						}
						vinterfaceLcuuid := common.GenerateUUID(vxnetId + borderId)
						retVInterfaces = append(retVInterfaces, model.VInterface{
							Lcuuid:        vinterfaceLcuuid,
							Type:          common.VIF_TYPE_LAN,
							Mac:           common.VIF_DEFAULT_MAC,
							DeviceType:    common.VIF_DEVICE_TYPE_VROUTER,
							DeviceLcuuid:  routerLcuuid,
							NetworkLcuuid: common.GenerateUUID(vxnetId),
							VPCLcuuid:     vpcLcuuid,
							RegionLcuuid:  regionLcuuid,
						})

						privateIP := net.Get("border_private_ip").MustString()
						if privateIP == "" {
							continue
						}
						retIPs = append(retIPs, model.IP{
							Lcuuid:           common.GenerateUUID(vinterfaceLcuuid + privateIP),
							VInterfaceLcuuid: vinterfaceLcuuid,
							IP:               privateIP,
							SubnetLcuuid: common.GenerateUUID(
								common.GenerateUUID(vxnetId),
							),
							RegionLcuuid: regionLcuuid,
						})
					}
				}
			}
		}
	}
	log.Info("get routers complete")
	return retVRouters, retRoutingTables, retVInterfaces, retIPs, nil
}
