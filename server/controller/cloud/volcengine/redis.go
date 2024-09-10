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

package volcengine

import (
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/volcengine/volcengine-go-sdk/service/redis"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

func (v *VolcEngine) getRedisInstances(regionID string, sess *session.Session) ([]model.RedisInstance, []model.VInterface, []model.IP, error) {
	log.Debug("get redis instances starting", logger.NewORGPrefix(v.orgID))
	var rediss []model.RedisInstance
	var vinterfaces []model.VInterface
	var ips []model.IP

	var retRediss []*redis.InstanceForDescribeDBInstancesOutput
	var pageNumber, pageSize int32 = 1, 100
	for {
		result, err := redis.New(sess).DescribeDBInstances(&redis.DescribeDBInstancesInput{RegionId: &regionID, PageNumber: &pageNumber, PageSize: &pageSize})
		if err != nil {
			log.Errorf("request volcengine (redis.DescribeDBInstances) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.RedisInstance{}, []model.VInterface{}, []model.IP{}, err
		}
		retRediss = append(retRediss, result.Instances...)
		if len(result.Instances) < int(pageSize) {
			break
		}
		pageSize += 1
	}

	for _, r := range retRediss {
		if r == nil || r.InstanceId == nil {
			continue
		}

		redisDetail, err := redis.New(sess).DescribeDBInstanceDetail(&redis.DescribeDBInstanceDetailInput{InstanceId: r.InstanceId})
		if err != nil {
			log.Errorf("request volcengine (redis.DescribeDBInstanceDetail) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.RedisInstance{}, []model.VInterface{}, []model.IP{}, err
		}

		redisID := v.getStringPointerValue(r.InstanceId)
		redisLcuuid := common.GetUUIDByOrgID(v.orgID, redisID)
		redisName := v.getStringPointerValue(redisDetail.InstanceName)
		var azLcuuid string
		if len(redisDetail.ZoneIds) == 1 {
			azLcuuid = common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(redisDetail.ZoneIds[0]))
		}
		vpcLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(redisDetail.VpcId))
		retRedis := model.RedisInstance{
			Lcuuid:       redisLcuuid,
			Name:         redisName,
			Label:        redisID,
			State:        vmStates[v.getStringPointerValue(redisDetail.Status)],
			Version:      "Redis " + v.getStringPointerValue(r.EngineVersion),
			AZLcuuid:     azLcuuid,
			VPCLcuuid:    vpcLcuuid,
			RegionLcuuid: v.regionLcuuid,
		}

		networkLcuuid := common.NETWORK_ISP_LCUUID
		subnetLcuuid := common.SUBNET_ISP_LCUUID
		subnetID := v.getStringPointerValue(redisDetail.SubnetId)
		if subnetID != "" {
			networkLcuuid = common.GetUUIDByOrgID(v.orgID, subnetID)
			subnetLcuuid = common.GetUUIDByOrgID(v.orgID, networkLcuuid)
		}
		for _, con := range redisDetail.VisitAddrs {
			if con == nil {
				continue
			}
			conIP := v.getStringPointerValue(con.VIP)
			var netType int
			networkType := v.getStringPointerValue(con.AddrType)
			switch networkType {
			case "Private":
				netType = common.VIF_TYPE_LAN
				retRedis.InternalHost = conIP
			case "Public":
				netType = common.VIF_TYPE_WAN
				retRedis.PublicHost = conIP
			default:
				log.Infof("invalid network type (%s)", networkType, logger.NewORGPrefix(v.orgID))
				continue
			}
			netID := v.getStringPointerValue(con.EipId)
			if netID == "" {
				netID = common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(con.Address)+conIP)
			}
			vinterfaceLcuuid := common.GetUUIDByOrgID(v.orgID, netID+conIP)
			vinterfaces = append(vinterfaces, model.VInterface{
				Lcuuid:        vinterfaceLcuuid,
				Type:          netType,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceLcuuid:  redisLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
				VPCLcuuid:     vpcLcuuid,
				NetworkLcuuid: networkLcuuid,
				RegionLcuuid:  v.regionLcuuid,
			})

			ips = append(ips, model.IP{
				Lcuuid:           common.GetUUIDByOrgID(v.orgID, netID),
				VInterfaceLcuuid: vinterfaceLcuuid,
				IP:               conIP,
				SubnetLcuuid:     subnetLcuuid,
				RegionLcuuid:     v.regionLcuuid,
			})
		}
		rediss = append(rediss, retRedis)
	}
	log.Debug("get redis instances complete", logger.NewORGPrefix(v.orgID))
	return rediss, vinterfaces, ips, nil
}
