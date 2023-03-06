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

package huawei

import (
	"fmt"

	"github.com/bitly/go-simplejson"
	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (h *HuaWei) getVPCs() ([]model.VPC, []model.VRouter, []model.RoutingTable, error) {
	var vpcs []model.VPC
	var vrouters []model.VRouter
	var routingTables []model.RoutingTable
	for project, token := range h.projectTokenMap {
		jvpcs, err := h.getRawData(
			fmt.Sprintf("https://vpc.%s.%s/v1/%s/vpcs", project.name, h.config.URLDomain, project.id), token.token, "vpcs",
		)
		if err != nil {
			log.Errorf("request failed: %v", err)
			return nil, nil, nil, err
		}

		regionLcuuid := h.projectNameToRegionLcuuid(project.name)
		for i := range jvpcs {
			jv := jvpcs[i]
			name := jv.Get("name").MustString()
			if !cloudcommon.CheckJsonAttributes(jv, []string{"id", "name"}) {
				log.Infof("exclude vpc: %s, missing attr", name)
				continue
			}
			id := jv.Get("id").MustString()
			vpc := model.VPC{
				Lcuuid:       id,
				Name:         name,
				RegionLcuuid: regionLcuuid,
			}
			cidr, ok := jv.CheckGet("cidr")
			if ok {
				vpc.CIDR = cidr.MustString()
			}
			vpcs = append(vpcs, vpc)
			h.toolDataSet.vpcLcuuids = append(h.toolDataSet.vpcLcuuids, id)
			h.toolDataSet.regionLcuuidToResourceNum[regionLcuuid]++

			vrouterLcuuid := common.GenerateUUID(vpc.Lcuuid)
			vrouters = append(
				vrouters,
				model.VRouter{
					Lcuuid:       vrouterLcuuid,
					Name:         name,
					RegionLcuuid: regionLcuuid,
					VPCLcuuid:    vpc.Lcuuid,
				},
			)
			h.toolDataSet.vpcLcuuidToVRouterLcuuid[vpc.Lcuuid] = vrouterLcuuid
			routingTables = append(routingTables, h.formatRoutingTables(jv, id, vrouterLcuuid)...)
		}

		rts, err := h.getPartialRoutingTables(project.name, token.token)
		if err != nil {
			return nil, nil, nil, err
		}
		routingTables = append(routingTables, rts...)
	}
	return vpcs, vrouters, routingTables, nil
}

func (h *HuaWei) formatRoutingTables(jVPC *simplejson.Json, vpcLcuuid, vrouterLcuuid string) (routingTables []model.RoutingTable) {
	jRTs, ok := jVPC.CheckGet("routes")
	if !ok {
		return
	}
	for i := range jRTs.MustArray() {
		jRT := jRTs.GetIndex(i)
		if !cloudcommon.CheckJsonAttributes(jRT, []string{"destination", "nexthop"}) {
			continue
		}
		destination := jRT.Get("destination").MustString()
		var nexthopType string
		nexthop := jRT.Get("nexthop").MustString()
		natLcuuid, ok := h.toolDataSet.keyToNATGatewayLcuuid[VPCIPKey{vpcLcuuid, nexthop}]
		if destination == "0.0.0.0/0" && ok {
			nexthop = natLcuuid
			nexthopType = common.ROUTING_TABLE_TYPE_NAT_GATEWAY
		} else {
			nexthopType = common.ROUTING_TABLE_TYPE_IP
		}
		routingTables = append(
			routingTables,
			model.RoutingTable{
				Lcuuid:        common.GenerateUUID(vpcLcuuid + destination + nexthop),
				VRouterLcuuid: vrouterLcuuid,
				Destination:   destination,
				Nexthop:       nexthop,
				NexthopType:   nexthopType,
			},
		)
	}
	return
}

func (h *HuaWei) getPartialRoutingTables(projectName, token string) (routingTables []model.RoutingTable, err error) {
	jRoutes, err := h.getRawData(
		fmt.Sprintf("https://vpc.%s.%s/v2.0/vpc/routes", projectName, h.config.URLDomain), token, "routes",
	)
	if err != nil {
		log.Errorf("request failed: %v", err)
		return
	}

	requiredAttrs := []string{"id", "vpc_id", "destination", "type", "nexthop"}
	for i := range jRoutes {
		jR := jRoutes[i]
		id := jR.Get("id").MustString()
		if !cloudcommon.CheckJsonAttributes(jR, requiredAttrs) {
			log.Infof("exclude routing_table: %s, missing attr", id)
			continue
		}
		rType := jR.Get("type").MustString()
		if rType != "peering" {
			log.Infof("exclude routing_table: %s, missing support type: %s", id, rType)
			continue
		}
		routingTables = append(
			routingTables,
			model.RoutingTable{
				Lcuuid:        id,
				VRouterLcuuid: h.toolDataSet.vpcLcuuidToVRouterLcuuid[jR.Get("vpc_id").MustString()],
				Destination:   jR.Get("destination").MustString(),
				NexthopType:   common.ROUTING_TABLE_TYPE_PEER_CONNECTION,
				Nexthop:       jR.Get("nexthop").MustString(),
			},
		)
	}
	return
}
