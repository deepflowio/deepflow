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

package aliyun

import (
	r_kvstore "github.com/aliyun/alibaba-cloud-sdk-go/services/r-kvstore"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (a *Aliyun) getRedisInstances(region model.Region) (
	[]model.RedisInstance, []model.VInterface, []model.IP, error,
) {
	var retRedisInstances []model.RedisInstance
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	log.Debug("get redis_instances starting")
	request := r_kvstore.CreateDescribeInstancesRequest()
	response, err := a.getRedisResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retRedisInstances, retVInterfaces, retIPs, err
	}

	for _, r := range response {
		instances, _ := r.Get("KVStoreInstance").Array()
		for i := range instances {
			redis := r.Get("KVStoreInstance").GetIndex(i)

			err := a.checkRequiredAttributes(
				redis,
				[]string{
					"InstanceId", "InstanceName", "VpcId", "ZoneId", "EngineVersion",
				},
			)
			if err != nil {
				continue
			}

			redisId := redis.Get("InstanceId").MustString()
			redisName := redis.Get("InstanceName").MustString()
			if redisName == "" {
				redisName = redisId
			}
			redisStatus := redis.Get("InstanceStatus").MustString()
			if redisStatus != "Normal" {
				log.Infof("redis (%s) invalid status (%s)", redisName, redisStatus)
				continue
			}
			vpcId := redis.Get("VpcId").MustString()
			zoneId := redis.Get("ZoneId").MustString()

			// 获取额外属性信息
			attrRequest := r_kvstore.CreateDescribeInstanceAttributeRequest()
			attrRequest.InstanceId = redisId
			attrResponse, err := a.getRedisAttributeResponse(region.Label, attrRequest)
			if err != nil {
				log.Error(err)
				return []model.RedisInstance{}, []model.VInterface{}, []model.IP{}, err
			}

			internalHost := ""
			publicHost := ""
			for _, rAttr := range attrResponse {
				for j := range rAttr.Get("DBInstanceAttribute").MustArray() {
					attr := rAttr.Get("DBInstanceAttribute").GetIndex(j)
					if attr.Get("PrivateIp").MustString() != "" {
						internalHost = attr.Get("ConnectionDomain").MustString()
					} else {
						publicHost = attr.Get("ConnectionDomain").MustString()
					}
				}
			}

			redisLcuuid := common.GenerateUUIDByOrgID(a.orgID, redisId)
			vpcLcuuid := common.GenerateUUIDByOrgID(a.orgID, vpcId)
			retRedisInstance := model.RedisInstance{
				Lcuuid:       redisLcuuid,
				Name:         redisName,
				Label:        redisId,
				VPCLcuuid:    vpcLcuuid,
				AZLcuuid:     common.GenerateUUIDByOrgID(a.orgID, a.uuidGenerate+"_"+zoneId),
				RegionLcuuid: a.getRegionLcuuid(region.Lcuuid),
				InternalHost: internalHost,
				PublicHost:   publicHost,
				State:        common.REDIS_STATE_RUNNING,
				Version:      "Redis " + redis.Get("EngineVersion").MustString(),
			}
			retRedisInstances = append(retRedisInstances, retRedisInstance)
			a.azLcuuidToResourceNum[retRedisInstance.AZLcuuid]++
			a.regionLcuuidToResourceNum[retRedisInstance.RegionLcuuid]++

			// 获取接口信息
			tmpVInterfaces, tmpIPs, err := a.getRedisPorts(region, redisId)
			if err != nil {
				return []model.RedisInstance{}, []model.VInterface{}, []model.IP{}, err
			}
			retVInterfaces = append(retVInterfaces, tmpVInterfaces...)
			retIPs = append(retIPs, tmpIPs...)
		}
	}
	log.Debug("get redis_instances complete")
	return retRedisInstances, retVInterfaces, retIPs, nil
}

func (a *Aliyun) getRedisPorts(region model.Region, redisId string) ([]model.VInterface, []model.IP, error) {
	var retVInterfaces []model.VInterface
	var retIPs []model.IP

	request := r_kvstore.CreateDescribeDBInstanceNetInfoRequest()
	request.InstanceId = redisId
	response, err := a.getRedisVInterfaceResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return []model.VInterface{}, []model.IP{}, err
	}

	redisLcuuid := common.GenerateUUIDByOrgID(a.orgID, redisId)
	for _, rNet := range response {
		for j := range rNet.Get("InstanceNetInfo").MustArray() {
			net := rNet.Get("InstanceNetInfo").GetIndex(j)

			ip := net.Get("IPAddress").MustString()
			if ip == "" {
				continue
			}
			portLcuuid := common.GenerateUUIDByOrgID(a.orgID, redisLcuuid+ip)
			portType := common.VIF_TYPE_LAN
			vpcLcuuid := common.GenerateUUIDByOrgID(a.orgID, net.Get("VPCId").MustString())
			networkLcuuid := common.GenerateUUIDByOrgID(a.orgID, net.Get("VSwitchId").MustString())
			if net.Get("IPType").MustString() == "Public" {
				portType = common.VIF_TYPE_WAN
				networkLcuuid = common.NETWORK_ISP_LCUUID
			}
			retVInterface := model.VInterface{
				Lcuuid:        portLcuuid,
				Type:          portType,
				Mac:           common.VIF_DEFAULT_MAC,
				DeviceLcuuid:  redisLcuuid,
				DeviceType:    common.VIF_DEVICE_TYPE_REDIS_INSTANCE,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
				RegionLcuuid:  a.getRegionLcuuid(region.Lcuuid),
			}
			retVInterfaces = append(retVInterfaces, retVInterface)

			retIP := model.IP{
				Lcuuid:           common.GenerateUUIDByOrgID(a.orgID, portLcuuid+ip),
				VInterfaceLcuuid: portLcuuid,
				IP:               ip,
				SubnetLcuuid:     common.GenerateUUIDByOrgID(a.orgID, networkLcuuid),
				RegionLcuuid:     a.getRegionLcuuid(region.Lcuuid),
			}
			retIPs = append(retIPs, retIP)
		}
	}
	return retVInterfaces, retIPs, nil
}
