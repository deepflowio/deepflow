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

type SecurityGroup struct {
	DataProvider
	toolData *securityGroupToolData
}

func NewSecurityGroup() *SecurityGroup {
	dp := &SecurityGroup{newDataProvider(ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_EN), new(securityGroupToolData)}
	dp.setGenerator(dp)
	return dp
}

func (h *SecurityGroup) generate() (data []common.ResponseElem, err error) {
	err = h.toolData.init().load()
	for _, item := range h.toolData.sgs {
		data = append(data, h.generateOne(item))
	}
	return
}

func (h *SecurityGroup) generateOne(item mysql.SecurityGroup) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["REGION_NAME"] = h.toolData.regionLcuuidToName[item.Region]
	d["DOMAIN_NAME"] = h.toolData.domainLcuuidToName[item.Domain]
	d["EPC_NAME"] = h.toolData.vpcIDToName[item.VPCID]
	d["VMS"] = h.toolData.sgIDToVMInfos[item.ID]
	d["VM_COUNT"] = len(h.toolData.sgIDToVMInfos[item.ID])
	d["SECURITY_GROUP_RULE_COUNT"] = h.toolData.sgIDToRuleCount[item.ID]

	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

type securityGroupToolData struct {
	sgs []mysql.SecurityGroup

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
	vpcIDToName        map[int]string

	sgIDToVMInfos   map[int][]map[string]interface{}
	sgIDToRuleCount map[int]int
}

func (td *securityGroupToolData) init() *securityGroupToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)

	td.sgIDToVMInfos = make(map[int][]map[string]interface{})
	td.sgIDToRuleCount = make(map[int]int)
	return td
}

func (td *securityGroupToolData) load() error {
	var err error
	td.sgs, err = UnscopedFind[mysql.SecurityGroup]()
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

	vms, err := Select[mysql.VM]([]string{"id", "name"})
	if err != nil {
		return err
	}
	vmIDToName := make(map[int]string)
	for _, item := range vms {
		vmIDToName[item.ID] = item.Name
	}
	vmSGs, err := Select[mysql.VMSecurityGroup]([]string{"vm_id", "sg_id"})
	if err != nil {
		return err
	}
	for _, item := range vmSGs {
		td.sgIDToVMInfos[item.SecurityGroupID] = append(td.sgIDToVMInfos[item.SecurityGroupID], map[string]interface{}{"ID": item.VMID, "NAME": vmIDToName[item.VMID]})
	}

	sgRules, err := Select[mysql.SecurityGroupRule]([]string{"sg_id"})
	if err != nil {
		return err
	}
	for _, item := range sgRules {
		td.sgIDToRuleCount[item.SecurityGroupID]++
	}
	return nil
}
