/**
 * Copyright (c) 2023 Yunshan Networks
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

package mysql

import (
	"golang.org/x/exp/slices"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type RedisInstance struct {
	DataProvider
	dataTool *redisInstanceToolData
}

func NewRedisInstance() *RedisInstance {
	dp := &RedisInstance{newDataProvider(ctrlrcommon.RESOURCE_TYPE_REDIS_INSTANCE_EN), new(redisInstanceToolData)}
	dp.setGenerator(dp)
	return dp
}

func (v *RedisInstance) generate() (data []common.ResponseElem, err error) {
	err = v.dataTool.Init().Load()
	for _, item := range v.dataTool.redisInstances {
		data = append(data, v.generateOne(item))
	}
	return
}

func (v *RedisInstance) generateOne(item mysql.RedisInstance) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["DOMAIN_NAME"] = v.dataTool.domainLcuuidToName[item.Domain]
	d["REGION_NAME"] = v.dataTool.regionLcuuidToName[item.Region]
	d["AZ_NAME"] = v.dataTool.azLcuuidToName[item.AZ]
	d["EPC_NAME"] = v.dataTool.vpcIDToName[item.VPCID]
	d["NETS"] = v.dataTool.redisInsIDToNetworkInfos[item.ID]
	d["WAN_IPS"] = v.dataTool.redisInsIDToWANIPs[item.ID]
	d["LAN_IPS"] = v.dataTool.redisInsIDToLANIPs[item.ID]
	d["ALL_IPS"] = append(v.dataTool.redisInsIDToWANIPs[item.ID], v.dataTool.redisInsIDToLANIPs[item.ID]...)

	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

type redisInstanceToolData struct {
	redisInstances []mysql.RedisInstance

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
	azLcuuidToName     map[string]string
	vpcIDToName        map[int]string

	redisInsIDToNetworkInfos map[int][]map[string]interface{}
	redisInsIDToWANIPs       map[int][]string
	redisInsIDToLANIPs       map[int][]string
}

func (td *redisInstanceToolData) Init() *redisInstanceToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.azLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)

	td.redisInsIDToNetworkInfos = make(map[int][]map[string]interface{})
	td.redisInsIDToWANIPs = make(map[int][]string)
	td.redisInsIDToLANIPs = make(map[int][]string)
	return td
}

func (td *redisInstanceToolData) Load() (err error) {
	td.redisInstances, err = UnscopedOrderFind[mysql.RedisInstance]("created_at DESC")
	if err != nil {
		return err
	}

	domains, err := Select[mysql.Domain]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}

	regions, err := Select[mysql.Region]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}

	azs, err := Select[mysql.AZ]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range azs {
		td.azLcuuidToName[item.Lcuuid] = item.Name
	}

	vpcs, err := Select[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	networks, err := Select[mysql.Network]([]string{"id", "name"})
	if err != nil {
		return err
	}
	idToNetwork := make(map[int]mysql.Network)
	for _, item := range networks {
		idToNetwork[item.ID] = item
	}

	vifs, err := SelectWithQuery[mysql.VInterface]([]string{"id", "subnetid", "deviceid"}, "devicetype = ?", ctrlrcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE)
	if err != nil {
		return err
	}
	vifIDs := make([]int, 0, len(vifs))
	for _, item := range vifs {
		vifIDs = append(vifIDs, item.ID)
	}
	wanIPs, err := SelectWithQuery[mysql.WANIP]([]string{"vifid", "ip"}, "vifid in (?)", vifIDs)
	if err != nil {
		return err
	}
	vifIDToWANIPs := make(map[int][]string)
	for _, item := range wanIPs {
		vifIDToWANIPs[item.VInterfaceID] = append(vifIDToWANIPs[item.VInterfaceID], item.IP)
	}
	lanIPs, err := SelectWithQuery[mysql.LANIP]([]string{"vifid", "ip"}, "vifid in (?)", vifIDs)
	if err != nil {
		return err
	}
	vifIDToLANIPs := make(map[int][]string)
	for _, item := range lanIPs {
		vifIDToLANIPs[item.VInterfaceID] = append(vifIDToLANIPs[item.VInterfaceID], item.IP)
	}
	redisInsIDToNetworkIDs := make(map[int][]int)
	for _, item := range vifs {
		if slices.Contains(redisInsIDToNetworkIDs[item.DeviceID], item.NetworkID) {
			redisInsIDToNetworkIDs[item.DeviceID] = append(redisInsIDToNetworkIDs[item.DeviceID], item.NetworkID)
			td.redisInsIDToNetworkInfos[item.DeviceID] = append(td.redisInsIDToNetworkInfos[item.DeviceID], map[string]interface{}{"VL2_ID": item.NetworkID, "VL2_NAME": idToNetwork[item.NetworkID].Name})
		}
		td.redisInsIDToWANIPs[item.DeviceID] = append(td.redisInsIDToWANIPs[item.DeviceID], vifIDToWANIPs[item.ID]...)
		td.redisInsIDToLANIPs[item.DeviceID] = append(td.redisInsIDToLANIPs[item.DeviceID], vifIDToLANIPs[item.ID]...)
	}
	return nil
}
