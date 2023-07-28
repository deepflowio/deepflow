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

type VM struct {
	DataProvider
	dataTool *vmToolData
}

func NewVM() *VM {
	dp := &VM{newDataProvider(ctrlrcommon.RESOURCE_TYPE_VM_EN), new(vmToolData)}
	dp.setGenerator(dp)
	return dp
}

func (v *VM) generate() (data []common.ResponseElem, err error) {
	err = v.dataTool.Init().Load()
	for _, item := range v.dataTool.vms {
		data = append(data, v.generateOne(item))
	}
	return
}

func (v *VM) generateOne(item mysql.VM) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["DOMAIN_NAME"] = v.dataTool.domainLcuuidToName[item.Domain]
	d["REGION_NAME"] = v.dataTool.regionLcuuidToName[item.Region]
	d["AZ_NAME"] = v.dataTool.azLcuuidToName[item.AZ]
	d["EPC_NAME"] = v.dataTool.vpcIDToName[item.VPCID]
	d["HOST_ID"] = v.dataTool.hostIPToID[item.LaunchServer]
	d["HOST_NAME"] = v.dataTool.hostIPToName[item.LaunchServer]
	d["POD_NODE_ID"] = ""
	d["POD_NODE_NAME"] = ""
	d["SECURITY_GROUPS"] = v.dataTool.vmIDToSecurityGroups[item.ID]
	d["SECURITY_GROUP_COUNT"] = ""
	networks := make([]map[string]interface{}, 0)
	for _, item := range v.dataTool.vmIDToNetworkIDs[item.ID] {
		networks = append(networks, map[string]interface{}{"ID": item, "NAME": v.dataTool.networkIDToName[item]})
	}
	d["SUBNETS"] = networks
	d["LAN_IPS"] = ""
	d["WAN_IPS"] = ""
	d["ALL_IPS"] = ""
	d["VIP"] = ""
	d["INTERFACES"] = ""
	d["INTERFACE_COUNT"] = ""
	d["VTAP_NAME"] = ""
	d["VTAP_ID"] = ""
	d["VTAP_LCUUID"] = ""
	d["VTAP_TYPE"] = ""
	d["VTAP_GROUP_LCUUID"] = ""
	d["VTAP_STATE"] = ""
	return d
}

type vmToolData struct {
	vms []mysql.VM

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
	azLcuuidToName     map[string]string
	vpcIDToName        map[int]string
	networkIDToName    map[int]string

	hostIPToID   map[string]int
	hostIPToName map[string]string

	vmIDToNetworkIDs     map[int][]int
	vmIDToSecurityGroups map[int][]map[string]interface{}
}

func (td *vmToolData) Init() *vmToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.azLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)
	td.networkIDToName = make(map[int]string)

	td.hostIPToID = make(map[string]int)
	td.hostIPToName = make(map[string]string)

	td.vmIDToNetworkIDs = make(map[int][]int)
	td.vmIDToSecurityGroups = make(map[int][]map[string]interface{})
	return td
}

func (td *vmToolData) Load() (err error) {
	td.vms, err = GetAll[mysql.VM]()
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

	hosts, err := Select[mysql.Host]([]string{"id", "ip"})
	if err != nil {
		return err
	}
	for _, item := range hosts {
		td.hostIPToID[item.IP] = item.ID
		td.hostIPToName[item.IP] = item.Name
	}

	vmSGs, err := Select[mysql.VMSecurityGroup]([]string{"vm_id", "sg_id"})

	if err != nil {
		return err
	}
	for _, item := range vmSGs {
		td.vmIDToSecurityGroups[item.VMID] = append(td.vmIDToSecurityGroups[item.VMID], map[string]interface{}{"ID": item.SecurityGroupID})
	}
	return
}
