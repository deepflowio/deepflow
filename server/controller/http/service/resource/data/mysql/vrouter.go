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

type VRouter struct {
	DataProvider
	dataTool *vrouterToolData
}

func NewVRouter() *VRouter {
	dp := &VRouter{newDataProvider(ctrlrcommon.RESOURCE_TYPE_VROUTER_EN), new(vrouterToolData)}
	dp.setGenerator(dp)
	return dp
}

func (v *VRouter) generate() (data []common.ResponseElem, err error) {
	err = v.dataTool.Init().Load()
	for _, item := range v.dataTool.vrouters {
		data = append(data, v.generateOne(item))
	}
	return
}

func (v *VRouter) generateOne(item mysql.VRouter) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["DOMAIN_NAME"] = v.dataTool.domainLcuuidToName[item.Domain]
	d["REGION_NAME"] = v.dataTool.regionLcuuidToName[item.Region]
	d["EPC_NAME"] = v.dataTool.vpcIDToName[item.VPCID]
	d["SUBNETS"] = v.dataTool.vrouterIDToNetworkInfos[item.ID]
	d["SUBNET_COUNT"] = len(v.dataTool.vrouterIDToNetworkInfos[item.ID])
	d["WAN_IPS"] = v.dataTool.vrouterIDToWANIPs[item.ID]
	d["LAN_IPS"] = v.dataTool.vrouterIDToLANIPs[item.ID]
	d["ALL_IPS"] = append(v.dataTool.vrouterIDToWANIPs[item.ID], v.dataTool.vrouterIDToLANIPs[item.ID]...)
	d["ROUTER_RULE_COUNT"] = v.dataTool.vrouterIDToRuleCount[item.ID]

	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

type vrouterToolData struct {
	vrouters []mysql.VRouter

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
	vpcIDToName        map[int]string

	vrouterIDToNetworkInfos map[int][]map[string]interface{}
	vrouterIDToWANIPs       map[int][]string
	vrouterIDToLANIPs       map[int][]string
	vrouterIDToRuleCount    map[int]int
}

func (td *vrouterToolData) Init() *vrouterToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)

	td.vrouterIDToNetworkInfos = make(map[int][]map[string]interface{})
	td.vrouterIDToWANIPs = make(map[int][]string)
	td.vrouterIDToLANIPs = make(map[int][]string)
	td.vrouterIDToRuleCount = make(map[int]int)
	return td
}

func (td *vrouterToolData) Load() (err error) {
	td.vrouters, err = UnscopedOrderFind[mysql.VRouter]("created_at DESC")
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

	vpcs, err := Select[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	rts, err := Select[mysql.RoutingTable]([]string{"vnet_id"})
	if err != nil {
		return err
	}
	for _, item := range rts {
		td.vrouterIDToRuleCount[item.VRouterID]++
	}

	vifs, err := SelectWithQuery[mysql.VInterface]([]string{"id", "subnetid", "deviceid"}, "devicetype = ?", ctrlrcommon.VIF_DEVICE_TYPE_VROUTER)
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
	vrouterIDToNetworkIDs := make(map[int][]int)
	for _, item := range vifs {
		if slices.Contains(vrouterIDToNetworkIDs[item.DeviceID], item.NetworkID) {
			vrouterIDToNetworkIDs[item.DeviceID] = append(vrouterIDToNetworkIDs[item.DeviceID], item.NetworkID)
			td.vrouterIDToNetworkInfos[item.DeviceID] = append(td.vrouterIDToNetworkInfos[item.DeviceID], map[string]interface{}{"ID": item.NetworkID})
		}
		td.vrouterIDToWANIPs[item.DeviceID] = append(td.vrouterIDToWANIPs[item.DeviceID], vifIDToWANIPs[item.ID]...)
		td.vrouterIDToLANIPs[item.DeviceID] = append(td.vrouterIDToLANIPs[item.DeviceID], vifIDToLANIPs[item.ID]...)
	}
	return nil
}
