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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type LB struct {
	DataProvider
	dataTool *lbToolData
}

func NewLB() *LB {
	dp := &LB{newDataProvider(ctrlrcommon.RESOURCE_TYPE_LB_EN), new(lbToolData)}
	dp.setGenerator(dp)
	return dp
}

func (v *LB) generate() (data []common.ResponseElem, err error) {
	err = v.dataTool.Init().Load()
	for _, item := range v.dataTool.lbs {
		data = append(data, v.generateOne(item))
	}
	return
}

func (v *LB) generateOne(item mysql.LB) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["DOMAIN_NAME"] = v.dataTool.domainLcuuidToName[item.Domain]
	d["REGION_NAME"] = v.dataTool.regionLcuuidToName[item.Region]
	d["EPC_NAME"] = v.dataTool.vpcIDToName[item.VPCID]
	d["IPS"] = v.dataTool.lbIDToIPs[item.ID]
	d["LB_LISTENERS"] = v.dataTool.lbIDToListenerInfos[item.ID]
	d["LB_RULE_COUNT"] = v.dataTool.lbIDToRuleCount[item.ID]

	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

type lbToolData struct {
	lbs []mysql.LB

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
	vpcIDToName        map[int]string

	lbIDToIPs           map[int][]string
	lbIDToListenerInfos map[int][]map[string]interface{}
	lbIDToRuleCount     map[int]int
}

func (td *lbToolData) Init() *lbToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)

	td.lbIDToIPs = make(map[int][]string)
	td.lbIDToListenerInfos = make(map[int][]map[string]interface{})
	td.lbIDToRuleCount = make(map[int]int)
	return td
}

func (td *lbToolData) Load() (err error) {
	td.lbs, err = UnscopedOrderFind[mysql.LB]("created_at DESC")
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

	lbListeners, err := Select[mysql.LBListener]([]string{"lb_id", "id", "name"})
	if err != nil {
		return err
	}
	for _, item := range lbListeners {
		td.lbIDToListenerInfos[item.LBID] = append(td.lbIDToListenerInfos[item.LBID], map[string]interface{}{"ID": item.ID, "NAME": item.Name})
	}
	lbTSs, err := Select[mysql.LBTargetServer]([]string{"lb_id", "id"})
	if err != nil {
		return err
	}
	for _, item := range lbTSs {
		td.lbIDToRuleCount[item.LBID]++
	}

	vifs, err := SelectWithQuery[mysql.VInterface]([]string{"id", "deviceid"}, "devicetype = ?", ctrlrcommon.VIF_DEVICE_TYPE_LB)
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
	for _, item := range vifs {
		td.lbIDToIPs[item.DeviceID] = append(vifIDToWANIPs[item.ID], vifIDToLANIPs[item.ID]...)
	}

	return nil
}
