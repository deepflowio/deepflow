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

package qingcloud

import (
	"sort"
	"strings"

	"github.com/mikioh/ipaddr"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (q *QingCloud) GetNetworks() ([]model.Network, []model.Subnet, error) {
	var retNetworks []model.Network
	var retSubnets []model.Subnet
	var vxnetIdToSubnetLcuuid map[string]string
	var vxnetIdToVPCLcuuid map[string]string
	var regionIdToVxnetIds map[string][]string

	log.Info("get networks starting")

	vxnetIdToVPCLcuuid = make(map[string]string)
	vxnetIdToSubnetLcuuid = make(map[string]string)
	regionIdToVxnetIds = make(map[string][]string)
	for regionId, regionLcuuid := range q.RegionIdToLcuuid {
		kwargs := []*Param{{"zone", regionId}}
		response, err := q.GetResponse("DescribeVxnets", "vxnet_set", kwargs)
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}

		for _, r := range response {
			for i := range r.MustArray() {
				network := r.GetIndex(i)
				err := q.CheckRequiredAttributes(network, []string{
					"vxnet_type", "vxnet_id", "vxnet_name", "vpc_router_id",
				})
				if err != nil {
					continue
				}

				vxnetId := network.Get("vxnet_id").MustString()
				// 如果vxnet已存在，则跳过该vxnet
				// 主要针对系统自带子网，青云公有云页面不会展示
				if _, ok := vxnetIdToVPCLcuuid[vxnetId]; ok {
					regionIdToVxnetIds[regionId] = append(
						regionIdToVxnetIds[regionId], vxnetId,
					)
					continue
				}
				networkLcuuid := common.GenerateUUIDByOrgID(q.orgID, vxnetId)
				if vxnetId == q.defaultVxnetName {
					networkLcuuid = common.GenerateUUIDByOrgID(q.orgID, vxnetId+regionLcuuid)
				}
				vxnetName := network.Get("vxnet_name").MustString()
				if vxnetName == "" {
					vxnetName = vxnetId
				}

				subnetCidr := ""
				routerId := ""
				if _, ok := network.CheckGet("router"); ok {
					subnetCidr = network.Get("router").Get("ip_network").MustString()
				} else {
					// 自管网络需要额外获取cidr
					// 匹配规则: "controller":"pitrix"  + "vxnet_name":"vpc-***" + "vxnet_type":0
					vxnetType := network.Get("vxnet_type").MustInt()
					if vxnetType == 0 && strings.HasPrefix(vxnetName, "vpc-") &&
						network.Get("controller").MustString() == "pitrix" {
						routerId, subnetCidr, err = q.getSelfMgmtNetworkInfo(regionId, vxnetId)
						if err != nil {
							return nil, nil, err
						}
					}
				}
				// 生成子网数据
				vpcLcuuid := ""
				netType := common.NETWORK_TYPE_LAN
				vpcRouterId := network.Get("vpc_router_id").MustString()
				if vpcRouterId != "" {
					vpcLcuuid = common.GenerateUUIDByOrgID(q.orgID, vpcRouterId)
				} else if routerId != "" {
					vpcLcuuid = common.GenerateUUIDByOrgID(q.orgID, routerId)
				} else {
					vpcLcuuid = common.GenerateUUIDByOrgID(q.orgID, q.UuidGenerate+"_default_vpc_"+regionLcuuid)
					netType = common.NETWORK_TYPE_WAN
				}
				// 判断是否为多可用区
				zoneId := network.Get("zone_id").MustString()
				azLcuuid := "multi"
				index := sort.SearchStrings(q.ZoneNames, zoneId)
				if index < len(q.ZoneNames) && q.ZoneNames[index] == zoneId {
					azLcuuid = common.GenerateUUIDByOrgID(q.orgID, q.UuidGenerate+"_"+zoneId)
				}

				vxnetIdToVPCLcuuid[vxnetId] = vpcLcuuid
				regionIdToVxnetIds[regionId] = append(
					regionIdToVxnetIds[regionId], vxnetId,
				)
				retNetworks = append(retNetworks, model.Network{
					Lcuuid:         networkLcuuid,
					Name:           vxnetName,
					Label:          vxnetId,
					SegmentationID: 1,
					TunnelID:       network.Get("vni").MustInt(),
					VPCLcuuid:      vpcLcuuid,
					Shared:         false,
					External:       false,
					NetType:        netType,
					AZLcuuid:       azLcuuid,
					RegionLcuuid:   regionLcuuid,
				})
				q.regionLcuuidToResourceNum[regionLcuuid]++
				q.azLcuuidToResourceNum[azLcuuid]++

				// 生成网段信息
				if subnetCidr == "" {
					continue
				}
				subnetLcuuid := common.GenerateUUIDByOrgID(q.orgID, networkLcuuid)
				vxnetIdToSubnetLcuuid[vxnetId] = subnetLcuuid
				retSubnets = append(retSubnets, model.Subnet{
					Lcuuid:        subnetLcuuid,
					Name:          vxnetName,
					CIDR:          subnetCidr,
					NetworkLcuuid: networkLcuuid,
					VPCLcuuid:     vpcLcuuid,
				})
			}
		}
	}

	q.regionIdToVxnetIds = regionIdToVxnetIds
	q.VxnetIdToVPCLcuuid = vxnetIdToVPCLcuuid
	q.VxnetIdToSubnetLcuuid = vxnetIdToSubnetLcuuid
	log.Info("get networks complete")
	return retNetworks, retSubnets, nil
}

func (q *QingCloud) getSelfMgmtNetworkInfo(regionId, vxnetId string) (string, string, error) {
	var routerId string
	var subnetCidr string

	kwargs := []*Param{
		{"zone", regionId},
		{"vxnet", vxnetId},
	}
	// 调用DescribeVxnetInstances获取router_id
	insResponse, err := q.GetResponse(
		"DescribeVxnetInstances", "instance_set", kwargs,
	)
	if err != nil {
		log.Error(err)
		return routerId, subnetCidr, err
	}

	for _, ins := range insResponse {
		for j := range ins.MustArray() {
			networkIns := ins.GetIndex(j)
			routerId = networkIns.Get("instance_name").MustString()
			if routerId == "" {
				continue
			}
			// 根据router_id获取vpc_network, 取最后一个23位网段作为cidr
			vpcCidr, ok := q.vpcIdToCidr[routerId]
			if !ok {
				continue
			}
			cidrParse, _ := ipaddr.Parse(vpcCidr)
			cidrLast := cidrParse.Last().IP.String()
			newCidrParse, _ := ipaddr.Parse(cidrLast + "/23")
			newCidrFirst := newCidrParse.First().IP.String()
			subnetCidr = newCidrFirst + "/23"
			break
		}
		if subnetCidr != "" {
			break
		}
	}

	return routerId, subnetCidr, nil
}
