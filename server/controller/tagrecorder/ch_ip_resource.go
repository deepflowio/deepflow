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
	"encoding/json"
	"strconv"
	"strings"

	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/db/redis"
)

type ChIPResource struct {
	UpdaterBase[mysql.ChIPResource, IPResourceKey]
}

func NewChIPResource() *ChIPResource {
	updater := &ChIPResource{
		UpdaterBase[mysql.ChIPResource, IPResourceKey]{
			resourceTypeName: RESOURCE_TYPE_CH_IP_RESOURCE,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (i *ChIPResource) generateNewData() (map[IPResourceKey]mysql.ChIPResource, bool) {
	keyToItem := make(map[IPResourceKey]mysql.ChIPResource)

	if redis.Redisdb == nil {
		return keyToItem, false
	}
	res, err := redis.Redisdb.HGetAll("ip").Result()
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
