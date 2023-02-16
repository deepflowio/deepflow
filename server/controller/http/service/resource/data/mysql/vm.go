/*
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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type VM struct {
	DataProvider
	dataTool *vmToolData
}

func NewVM() *VM {
	dp := &VM{newDataProvider(common.RESOURCE_TYPE_VM_EN), new(vmToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *VM) generate() (data []ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.vms {
		d := MySQLModelToMap(item)
		d["AZ_NAME"] = p.dataTool.azLcuuidToName[item.AZ]
		d["REGION_NAME"] = p.dataTool.regionLcuuidToName[item.Region]
		d["DOMAIN_NAME"] = p.dataTool.domainLcuuidToName[item.Domain]
		d["EPC_NAME"] = p.dataTool.vpcIDToName[item.VPCID]
		d["HOST_ID"] = p.dataTool.hostIPToID[item.LaunchServer]
		data = append(data, d)
	}
	return
}

type vmToolData struct {
	vms []mysql.VM

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
	azLcuuidToName     map[string]string
	vpcIDToName        map[int]string
	hostIPToID         map[string]int
}

func (td *vmToolData) Init() *vmToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.azLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)
	td.hostIPToID = make(map[string]int)
	return td
}

func (td *vmToolData) Load() (err error) {
	err = mysql.Db.Find(&td.vms).Error

	var domains []mysql.Domain
	err = mysql.Db.Select("lcuuid", "name").Find(&domains).Error
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}
	var regions []mysql.Region
	err = mysql.Db.Select("lcuuid", "name").Find(&regions).Error
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}
	var azs []mysql.AZ
	err = mysql.Db.Select("lcuuid", "name").Find(&azs).Error
	for _, item := range azs {
		td.azLcuuidToName[item.Lcuuid] = item.Name
	}
	var vpcs []mysql.VPC
	err = mysql.Db.Select("id", "name").Find(&vpcs).Error
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}
	var hosts []mysql.Host
	err = mysql.Db.Select("id", "ip").Find(&hosts).Error
	for _, item := range hosts {
		td.hostIPToID[item.IP] = item.ID
	}
	return
}
