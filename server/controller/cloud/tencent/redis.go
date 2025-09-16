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
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (t *Tencent) getRedisInstances(region string) ([]model.RedisInstance, []model.VInterface, []model.IP, error) {
	log.Debug("get redis instances starting", logger.NewORGPrefix(t.orgID))
	var rediss []model.RedisInstance
	var vinterfaces []model.VInterface
	var ips []model.IP

	resp, err := t.getResponse("redis", "2018-04-12", "DescribeInstances", region, "InstanceSet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("redis request tencent api error: (%s)", err.Error(), logger.NewORGPrefix(t.orgID))
		return []model.RedisInstance{}, []model.VInterface{}, []model.IP{}, err
	}
	for _, rData := range resp {
		redisID := rData.Get("InstanceId").MustString()
		redisLcuuid := common.GetUUIDByOrgID(t.orgID, redisID)
		redisName := rData.Get("InstanceName").MustString()
		zoneID := rData.Get("ZoneId").MustInt()
		azLcuuid, ok := t.azIDToLcuuid[zoneID]
		if !ok {
			log.Infof("redis (%s) az (id:%d) not in available zones", redisName, zoneID, logger.NewORGPrefix(t.orgID))
			continue
		}
		var redisState int
		if rData.Get("Status").MustInt() == 2 {
			redisState = common.REDIS_STATE_RUNNING
		}
		vpcLcuuid := common.GetUUIDByOrgID(t.orgID, rData.Get("UniqVpcId").MustString())
		retRedis := model.RedisInstance{
			Lcuuid:       redisLcuuid,
			Name:         redisName,
			Label:        redisID,
			State:        redisState,
			Version:      "Redis " + rData.Get("CurrentRedisVersion").MustString(),
			AZLcuuid:     azLcuuid,
			VPCLcuuid:    vpcLcuuid,
			RegionLcuuid: t.regionLcuuid,
		}
		t.azLcuuidMap[azLcuuid] = 0

		networkLcuuid := common.NETWORK_ISP_LCUUID
		subnetLcuuid := common.SUBNET_ISP_LCUUID
		subnetID := rData.Get("UniqSubnetId").MustString()
		if subnetID != "" {
			networkLcuuid = common.GetUUIDByOrgID(t.orgID, subnetID)
			subnetLcuuid = common.GetUUIDByOrgID(t.orgID, networkLcuuid+"_v4")
		}

		address := rData.Get("WanIp").MustString()
		vinterfaceLcuuid := common.GetUUIDByOrgID(t.orgID, redisID+address)
		vinterfaces = append(vinterfaces, model.VInterface{
			Lcuuid:        vinterfaceLcuuid,
			Type:          common.NETWORK_TYPE_LAN,
			Mac:           common.VIF_DEFAULT_MAC,
			DeviceLcuuid:  redisLcuuid,
			DeviceType:    common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
			VPCLcuuid:     vpcLcuuid,
			NetworkLcuuid: networkLcuuid,
			RegionLcuuid:  t.regionLcuuid,
		})

		ips = append(ips, model.IP{
			Lcuuid:           common.GetUUIDByOrgID(t.orgID, vinterfaceLcuuid+address),
			VInterfaceLcuuid: vinterfaceLcuuid,
			IP:               address,
			SubnetLcuuid:     subnetLcuuid,
			RegionLcuuid:     t.regionLcuuid,
		})
		rediss = append(rediss, retRedis)
	}
	log.Debug("get redis instances complete", logger.NewORGPrefix(t.orgID))
	return rediss, vinterfaces, ips, nil
}
