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

package tagrecorder

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
)

type ChIPResource struct {
	UpdaterBase[mysql.ChIPResource, IPResourceKey]
	ctx context.Context
}

func NewChIPResource(ctx context.Context) *ChIPResource {
	updater := &ChIPResource{
		UpdaterBase[mysql.ChIPResource, IPResourceKey]{
			resourceTypeName: RESOURCE_TYPE_CH_IP_RESOURCE,
		},
		ctx,
	}
	updater.dataGenerator = updater
	return updater
}

func getVMIdToUidMap() map[int]string {
	idToUidMap := map[int]string{}
	var vms []mysql.VM
	err := mysql.Db.Unscoped().Find(&vms).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(RESOURCE_TYPE_VM, err))
		return idToUidMap
	}
	for _, vm := range vms {
		idToUidMap[vm.ID] = vm.UID
	}
	return idToUidMap
}

func getRDSIdToUidMap() map[int]string {
	idToUidMap := map[int]string{}
	var rdsInstances []mysql.RDSInstance
	err := mysql.Db.Unscoped().Find(&rdsInstances).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(RESOURCE_TYPE_RDS, err))
		return idToUidMap
	}
	for _, rdsInstance := range rdsInstances {
		idToUidMap[rdsInstance.ID] = rdsInstance.UID
	}
	return idToUidMap
}

func getRedisIdToUidMap() map[int]string {
	idToUidMap := map[int]string{}
	var redisInstances []mysql.RedisInstance
	err := mysql.Db.Unscoped().Find(&redisInstances).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(RESOURCE_TYPE_REDIS, err))
		return idToUidMap
	}
	for _, redisInstance := range redisInstances {
		idToUidMap[redisInstance.ID] = redisInstance.UID
	}
	return idToUidMap
}

func getLBIdToUidMap() map[int]string {
	idToUidMap := map[int]string{}
	var lbs []mysql.LB
	err := mysql.Db.Unscoped().Find(&lbs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(RESOURCE_TYPE_LB, err))
		return idToUidMap
	}
	for _, lb := range lbs {
		idToUidMap[lb.ID] = lb.UID
	}
	return idToUidMap
}

func getNatgwIdToUidMap() map[int]string {
	idToUidMap := map[int]string{}
	var natGateways []mysql.NATGateway
	err := mysql.Db.Unscoped().Find(&natGateways).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(RESOURCE_TYPE_NAT_GATEWAY, err))
		return idToUidMap
	}
	for _, natGateway := range natGateways {
		idToUidMap[natGateway.ID] = natGateway.UID
	}
	return idToUidMap
}

func getVPCIdToUidMap() map[int]string {
	idToUidMap := map[int]string{}
	var vpcs []mysql.VPC
	err := mysql.Db.Unscoped().Find(&vpcs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(RESOURCE_TYPE_VPC, err))
		return idToUidMap
	}
	for _, vpc := range vpcs {
		idToUidMap[vpc.ID] = vpc.UID
	}
	return idToUidMap
}

func (i *ChIPResource) generateNewData() (map[IPResourceKey]mysql.ChIPResource, bool) {
	keyToItem := make(map[IPResourceKey]mysql.ChIPResource)
	vmIdToUidMap := getVMIdToUidMap()
	rdsIdToUidMap := getRDSIdToUidMap()
	redisIdToUidMap := getRedisIdToUidMap()
	lbIdToUidMap := getLBIdToUidMap()
	natgwIdToUidMap := getNatgwIdToUidMap()
	vpcIdToUidMap := getVPCIdToUidMap()
	if redis.RedisDB == nil {
		return keyToItem, false
	}
	res, err := redis.RedisDB.DimensionResource.HGetAll(i.ctx, "deepflow_dimension_resource_ip").Result()
	if err != nil {
		log.Error(err)
		return nil, false
	}
	for subnetIDIP, MultiResource := range res {
		subnetIDIPList := strings.Split(subnetIDIP, "-")
		if len(subnetIDIPList) != 2 {
			continue
		}
		subnetIDStr := subnetIDIPList[0]
		subnetID, err := strconv.Atoi(subnetIDStr)
		if err != nil {
			log.Error(err)
			return nil, false
		}
		if subnetID == 0 {
			continue
		}
		ip := subnetIDIPList[1]
		itemMap := make(map[string]interface{})
		itemMap["IP"] = ip
		MultiResourceMap := make(map[string]interface{})
		err = json.Unmarshal([]byte(MultiResource), &MultiResourceMap)
		if err != nil {
			log.Error(err)
			return nil, false
		}
		for _, tag := range CH_IP_RESOURCE_TAGS {
			multiIDTag := strings.ReplaceAll(tag, "vpc", "epc")
			multiIDTag = strings.ReplaceAll(multiIDTag, "router", "vgw")
			multiIDTag = strings.ReplaceAll(multiIDTag, "chost", "vm")
			multiIDTag = strings.ReplaceAll(multiIDTag, "natgw", "nat_gateway")
			multiIDTag = strings.ReplaceAll(multiIDTag, "dhcpgw", "dhcp_port")
			multiIDTag = strings.ReplaceAll(multiIDTag, "redis", "redis_instance")
			multiIDTag = strings.ReplaceAll(multiIDTag, "rds", "rds_instance")
			multiIDTag = strings.ReplaceAll(multiIDTag, "subnet", "vl2")
			multiIDTag = strings.ReplaceAll(multiIDTag, "pod_ns", "pod_namespace")
			multiIDTag = multiIDTag + "s"
			switch MultiResourceMap[multiIDTag].(type) {
			case []interface{}:
				if len(MultiResourceMap[multiIDTag].([]interface{})) > 0 {
					resource_value := MultiResourceMap[multiIDTag].([]interface{})[0]
					switch resource_value.(type) {
					case string:
						itemMap[strings.ToUpper(tag)] = resource_value.(string)
					case float64:
						itemMap[strings.ToUpper(tag)] = int(resource_value.(float64))
						// 当tag为_id的时候,添加uid信息
						switch strings.TrimSuffix(multiIDTag, "_ids") {
						case "vm":
							itemMap["uid"] = vmIdToUidMap[int(resource_value.(float64))]
						case "rds_instance":
							itemMap["uid"] = rdsIdToUidMap[int(resource_value.(float64))]
						case "redis_instance":
							itemMap["uid"] = redisIdToUidMap[int(resource_value.(float64))]
						case "lb":
							itemMap["uid"] = lbIdToUidMap[int(resource_value.(float64))]
						case "nat_gateway":
							itemMap["uid"] = natgwIdToUidMap[int(resource_value.(float64))]
						case "epc":
							itemMap["uid"] = vpcIdToUidMap[int(resource_value.(float64))]
						}

					}
				}
			}

		}
		itemStr, err := json.Marshal(itemMap)
		if err != nil {
			log.Error(err)
			return nil, false
		}
		itemStruct := mysql.ChIPResource{}
		err = json.Unmarshal(itemStr, &itemStruct)
		if err != nil {
			log.Error(err)
			return nil, false
		}
		keyToItem[IPResourceKey{IP: ip, SubnetID: subnetID}] = itemStruct
	}
	return keyToItem, true
}

func (i *ChIPResource) generateKey(dbItem mysql.ChIPResource) IPResourceKey {
	return IPResourceKey{IP: dbItem.IP, SubnetID: dbItem.SubnetID}
}

func (i *ChIPResource) generateUpdateInfo(oldItem, newItem mysql.ChIPResource) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	oldItemMap := make(map[string]interface{})
	newItemMap := make(map[string]interface{})
	oldItemStr, err := json.Marshal(oldItem)
	if err != nil {
		return nil, false
	}
	newItemStr, err := json.Marshal(newItem)
	if err != nil {
		return nil, false
	}
	err = json.Unmarshal(oldItemStr, &oldItemMap)
	if err != nil {
		return nil, false
	}
	err = json.Unmarshal(newItemStr, &newItemMap)
	if err != nil {
		return nil, false
	}
	for oldKey, oldValue := range oldItemMap {
		if oldValue != newItemMap[oldKey] {
			updateInfo[strings.ToLower(oldKey)] = newItemMap[oldKey]
		}
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
