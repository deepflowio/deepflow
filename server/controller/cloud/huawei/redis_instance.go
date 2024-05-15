/**
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

package huawei

import (
	"fmt"
	"strings"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (h *HuaWei) getRedisInstances() ([]model.RedisInstance, []model.VInterface, []model.IP, error) {
	stateStrToInt := map[string]int{
		"RUNNING": common.REDIS_STATE_RUNNING,
	}

	var rs []model.RedisInstance
	var vifs []model.VInterface
	var ips []model.IP
	for project, token := range h.projectTokenMap {
		jRs, err := h.getRawData(newRawDataGetContext(
			fmt.Sprintf("https://dcs.%s.%s/v2/%s/instances", project.name, h.config.Domain, project.id), token.token, "instances", pageQueryMethodOffset,
		))
		if err != nil {
			return nil, nil, nil, err
		}

		regionLcuuid := h.projectNameToRegionLcuuid(project.name)
		for i := range jRs {
			jRedis := jRs[i]
			if !cloudcommon.CheckJsonAttributes(jRedis, []string{"instance_id", "name", "status", "az_codes", "engine_version", "vpc_id", "subnet_id", "ip", "publicip_address"}) {
				continue
			}
			id := common.IDGenerateUUID(h.orgID, jRedis.Get("instance_id").MustString())
			name := jRedis.Get("name").MustString()
			state, ok := stateStrToInt[jRedis.Get("status").MustString()]
			if !ok {
				log.Infof("exclude redis_instance: %s, state: %s", id, jRedis.Get("status").MustString())
				continue
			}

			azNames := jRedis.Get("az_codes").MustStringArray()
			var azLcuuid string
			if len(azNames) == 1 && azNames[0] != "" {
				azLcuuid, ok = h.toolDataSet.azNameToAZLcuuid[azNames[0]]
				if !ok {
					log.Infof("exclude redis_instance: %s, az: %s not found", id, azNames[0])
					continue
				}
			}

			networkLcuuid := common.IDGenerateUUID(h.orgID, jRedis.Get("subnet_id").MustString())
			if networkLcuuid == "" {
				log.Infof("exclude rds_instance: %s, no subnet_id", id)
				continue
			}

			redis := model.RedisInstance{
				Lcuuid:       id,
				Name:         name,
				Label:        id,
				State:        state,
				Version:      "Redis " + jRedis.Get("engine_version").MustString(),
				InternalHost: jRedis.Get("ip").MustString(),
				PublicHost:   jRedis.Get("publicip_address").MustString(),
				VPCLcuuid:    common.IDGenerateUUID(h.orgID, jRedis.Get("vpc_id").MustString()),
				AZLcuuid:     azLcuuid,
				RegionLcuuid: regionLcuuid,
			}
			rs = append(rs, redis)
			h.toolDataSet.azLcuuidToResourceNum[azLcuuid]++
			h.toolDataSet.regionLcuuidToResourceNum[regionLcuuid]++

			for _, ip := range strings.Split(jRedis.Get("ip").MustString(), ",") {
				vif := model.VInterface{
					Lcuuid:        common.GenerateUUIDByOrgID(h.orgID, redis.Lcuuid+ip),
					Type:          common.VIF_TYPE_LAN,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceLcuuid:  redis.Lcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
					NetworkLcuuid: networkLcuuid,
					VPCLcuuid:     redis.VPCLcuuid,
					RegionLcuuid:  regionLcuuid,
				}
				vifs = append(vifs, vif)

				var subnetLcuuid string
				for _, subnet := range h.toolDataSet.networkLcuuidToSubnets[networkLcuuid] {
					if cloudcommon.IsIPInCIDR(ip, subnet.CIDR) {
						subnetLcuuid = subnet.Lcuuid
						break
					}
				}
				ip := model.IP{
					Lcuuid:           common.GenerateUUIDByOrgID(h.orgID, vif.Lcuuid+ip),
					VInterfaceLcuuid: vif.Lcuuid,
					IP:               strings.Trim(ip, " "),
					SubnetLcuuid:     subnetLcuuid,
					RegionLcuuid:     regionLcuuid,
				}
				ips = append(ips, ip)
			}

			for _, ip := range strings.Split(jRedis.Get("publicip_address").MustString(), ",") {
				vif := model.VInterface{
					Lcuuid:        common.GenerateUUIDByOrgID(h.orgID, redis.Lcuuid+ip),
					Type:          common.VIF_TYPE_WAN,
					Mac:           common.VIF_DEFAULT_MAC,
					DeviceLcuuid:  redis.Lcuuid,
					DeviceType:    common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
					NetworkLcuuid: common.NETWORK_ISP_LCUUID,
					VPCLcuuid:     redis.VPCLcuuid,
					RegionLcuuid:  regionLcuuid,
				}
				vifs = append(vifs, vif)

				ip := model.IP{
					Lcuuid:           common.GenerateUUIDByOrgID(h.orgID, vif.Lcuuid+ip),
					VInterfaceLcuuid: vif.Lcuuid,
					IP:               strings.Trim(ip, " "),
					RegionLcuuid:     regionLcuuid,
				}
				ips = append(ips, ip)
			}
		}
	}
	return rs, vifs, ips, nil
}
