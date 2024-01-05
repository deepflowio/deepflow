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
	"strings"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (q *QingCloud) GetNATGateways() (
	[]model.NATGateway, []model.VInterface, []model.IP, []model.NATVMConnection, error,
) {
	var retNATGateways []model.NATGateway
	var retVInterfaces []model.VInterface
	var retIPs []model.IP
	var retNATVMConns []model.NATVMConnection

	log.Info("get nat_gateways starting")

	natIdToLcuuid := make(map[string]string)
	for regionId, regionLcuuid := range q.RegionIdToLcuuid {
		vxnetIds, ok := q.regionIdToVxnetIds[regionId]
		if !ok {
			log.Debugf("no vxnetIds in region (%s)", regionId)
			continue
		}

		for _, vxnetId := range vxnetIds {
			kwargs := []*Param{
				{"zone", regionId},
				{"nfv_type", 1},
				{"vxnets.1", vxnetId},
				{"status.1", "active"},
				{"status.2", "stopped"},
			}
			response, err := q.GetResponse("DescribeNFVs", "nfv_set", kwargs)
			if err != nil {
				log.Error(err)
				return nil, nil, nil, nil, err
			}

			vpcLcuuid, ok := q.VxnetIdToVPCLcuuid[vxnetId]
			if !ok {
				log.Infof("vxnet (%s) not in any vpc", vxnetId)
				continue
			}

			for _, r := range response {
				for i := range r.MustArray() {
					nat := r.GetIndex(i)

					natId := nat.Get("nfv_id").MustString()
					natName := nat.Get("nfv_name").MustString()
					if natName == "" {
						natName = natId
					}
					if _, ok := natIdToLcuuid[natId]; ok {
						continue
					}
					natLcuuid := common.GenerateUUID(natId)

					eips := []string{}
					for j := range nat.Get("eips").MustArray() {
						ip := nat.Get("eips").GetIndex(j)
						eip := ip.Get("eip_addr").MustString()
						if eip != "" {
							eips = append(eips, eip)
						}
					}

					// 确定NAT网关与载体虚拟机的关联关系
					for j := range nat.Get("cluster").MustArray() {
						cluster := nat.Get("cluster").GetIndex(j)
						// 兼容私有云情况，光大环境中eip会在cluster中返回
						eip := cluster.Get("eip_addr").MustString()
						if eip != "" {
							eips = append(eips, eip)
						}
						for k := range cluster.Get("instances").MustArray() {
							instance := cluster.Get("instances").GetIndex(k)
							instanceId := instance.Get("instance_id").MustString()
							if instanceId == "" {
								continue
							}
							if _, ok := q.vmIdToVPCLcuuid[instanceId]; !ok {
								continue
							}
							retNATVMConns = append(retNATVMConns, model.NATVMConnection{
								Lcuuid:           common.GenerateUUID(natLcuuid + instanceId),
								NATGatewayLcuuid: natLcuuid,
								VMLcuuid:         common.GenerateUUID(instanceId),
							})
						}
					}

					retNATGateways = append(retNATGateways, model.NATGateway{
						Lcuuid:       natLcuuid,
						Name:         natName,
						Label:        natId,
						FloatingIPs:  strings.Join(eips, ","),
						VPCLcuuid:    vpcLcuuid,
						RegionLcuuid: regionLcuuid,
					})
					natIdToLcuuid[natId] = natLcuuid
					q.regionLcuuidToResourceNum[regionLcuuid]++

					// 生成NATGateway接口及IP信息
					if len(eips) > 0 {
						vinterfaceLcuuid := common.GenerateUUID(natLcuuid)
						retVInterfaces = append(retVInterfaces, model.VInterface{
							Lcuuid:        vinterfaceLcuuid,
							Type:          common.VIF_TYPE_WAN,
							Mac:           common.VIF_DEFAULT_MAC,
							DeviceType:    common.VIF_DEVICE_TYPE_NAT_GATEWAY,
							DeviceLcuuid:  natLcuuid,
							NetworkLcuuid: common.NETWORK_ISP_LCUUID,
							VPCLcuuid:     vpcLcuuid,
							RegionLcuuid:  regionLcuuid,
						})
						for _, eip := range eips {
							retIPs = append(retIPs, model.IP{
								Lcuuid:           common.GenerateUUID(vinterfaceLcuuid + eip),
								VInterfaceLcuuid: vinterfaceLcuuid,
								IP:               eip,
								RegionLcuuid:     regionLcuuid,
							})
						}
					}
				}
			}
		}
	}

	log.Info("get nat_gateways complete")
	return retNATGateways, retVInterfaces, retIPs, retNATVMConns, nil
}
