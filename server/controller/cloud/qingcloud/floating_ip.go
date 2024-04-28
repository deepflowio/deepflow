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
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (q *QingCloud) GetFloatingIPs() ([]model.VInterface, []model.IP, []model.FloatingIP, error) {
	var retVInterfaces []model.VInterface
	var retIPs []model.IP
	var retFloatingIPs []model.FloatingIP

	log.Info("get floating_ips starting")

	for regionId, regionLcuuid := range q.RegionIdToLcuuid {
		kwargs := []*Param{
			{"zone", regionId},
			{"status.1", "associated"},
		}
		response, err := q.GetResponse("DescribeEips", "eip_set", kwargs)
		if err != nil {
			log.Error(err)
			return nil, nil, nil, err
		}

		for _, r := range response {
			for i := range r.MustArray() {
				eip := r.GetIndex(i)

				eipId := eip.Get("eip_id").MustString()
				ip := eip.Get("eip_addr").MustString()
				deviceType := eip.Get("resource").Get("resource_type").MustString()
				if deviceType != "instance" {
					continue
				}
				resourceId := eip.Get("resource").Get("resource_id").MustString()
				vpcLcuuid, ok := q.vmIdToVPCLcuuid[resourceId]
				if !ok {
					log.Debugf("eip (%s) vpc not found", ip)
					continue
				}
				retFloatingIPs = append(retFloatingIPs, model.FloatingIP{
					Lcuuid:        common.GenerateUUIDByOrgID(q.orgID, eipId),
					IP:            ip,
					VMLcuuid:      common.GenerateUUIDByOrgID(q.orgID, resourceId),
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  regionLcuuid,
				})

				// 给LB或者NAT网关的关联虚拟机补充接口和IP
				if eip.Get("associate_mode").MustInt() != 1 {
					continue
				}
				nicId := eip.Get("resource").Get("nic_id").MustString()
				vinterfaceLcuuid := common.GenerateUUIDByOrgID(q.orgID, nicId+resourceId)
				retVInterfaces = append(retVInterfaces, model.VInterface{
					Lcuuid:        vinterfaceLcuuid,
					Type:          common.VIF_TYPE_WAN,
					Mac:           nicId,
					DeviceType:    common.VIF_DEVICE_TYPE_VM,
					DeviceLcuuid:  common.GenerateUUIDByOrgID(q.orgID, resourceId),
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     vpcLcuuid,
					RegionLcuuid:  regionLcuuid,
				})
				retIPs = append(retIPs, model.IP{
					Lcuuid:           common.GenerateUUIDByOrgID(q.orgID, vinterfaceLcuuid+ip),
					VInterfaceLcuuid: vinterfaceLcuuid,
					IP:               ip,
					RegionLcuuid:     regionLcuuid,
				})
			}
		}
	}

	log.Info("get floating_ips complete")
	return retVInterfaces, retIPs, retFloatingIPs, nil
}
