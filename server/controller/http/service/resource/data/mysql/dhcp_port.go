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
	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type DHCPPort struct {
	DataProvider
	dataTool *DHCPPortToolData
}

func NewDHCPPort() *DHCPPort {
	dp := &DHCPPort{newDataProvider(ctrlcommon.RESOURCE_TYPE_POD_NODE_EN), new(DHCPPortToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *DHCPPort) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.DHCPPorts {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *DHCPPort) generateOne(item mysql.DHCPPort) common.ResponseElem {
	d := MySQLModelToMap(item)
	if _, ok := d["VPC_ID"]; ok {
		d["EPC_ID"] = item.VPCID
		delete(d, "VPC_ID")
	}

	d["REGION_NAME"] = p.dataTool.regionLcuuidToName[item.Region]
	d["DOMAIN_NAME"] = p.dataTool.domainLcuuidToName[item.Domain]
	d["EPC_NAME"] = p.dataTool.vpcIDToName[item.VPCID]
	d["IP"] = nil

	for _, vifID := range p.dataTool.dhcpPortIDToVIFIDs[item.ID] {
		_, ok := p.dataTool.vifIDToVIF[vifID]
		if !ok {
			continue
		}

		vifIPIDs := p.dataTool.vifIDToIPRIDs[vifID]
		var isLanIP bool
		for _, vifIPID := range vifIPIDs {
			if ip, ok := p.dataTool.idToVIFIP[vifIPID]; ok {
				d["IP"] = ip.IP
				isLanIP = true
				break
			}
		}

		if !isLanIP {
			iprIDs := p.dataTool.vifIDToIPRIDs[vifID]
			for _, iprID := range iprIDs {
				ip, ok := p.dataTool.idToIPR[iprID]
				if ok {
					d["IP"] = ip.IP
					break
				}
			}
		}
	}

	return d
}

type DHCPPortToolData struct {
	DHCPPorts []mysql.DHCPPort

	regionLcuuidToName map[string]string
	domainLcuuidToName map[string]string
	vpcIDToName        map[int]string

	dhcpPortIDToVIFIDs map[int][]int
	vifIDToVIF         map[int]mysql.VInterface
	vifIDToVIFIPIDs    map[int][]int
	idToVIFIP          map[int]mysql.LANIP
	vifIDToIPRIDs      map[int][]int
	idToIPR            map[int]mysql.WANIP
}

func (td *DHCPPortToolData) Init() *DHCPPortToolData {
	td.regionLcuuidToName = make(map[string]string)
	td.domainLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)

	td.dhcpPortIDToVIFIDs = make(map[int][]int)
	td.vifIDToVIF = make(map[int]mysql.VInterface)
	td.vifIDToVIFIPIDs = make(map[int][]int)
	td.idToVIFIP = make(map[int]mysql.LANIP)
	td.vifIDToIPRIDs = make(map[int][]int)
	td.idToIPR = make(map[int]mysql.WANIP)

	return td
}

func (td *DHCPPortToolData) Load() (err error) {
	td.DHCPPorts, err = UnscopedFind[mysql.DHCPPort]()
	if err != nil {
		return err
	}

	regions, err := UnscopedSelect[mysql.Region]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}

	domains, err := UnscopedSelect[mysql.Domain]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}

	vpcs, err := UnscopedSelect[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	vifs, err := UnscopedFind[mysql.VInterface]()
	if err != nil {
		return err
	}
	for _, vif := range vifs {
		td.vifIDToVIF[vif.ID] = vif
	}
	for _, item := range vifs {
		switch item.DeviceType {
		case ctrlcommon.VIF_DEVICE_TYPE_DHCP_PORT:
			td.dhcpPortIDToVIFIDs[item.DeviceID] = append(td.dhcpPortIDToVIFIDs[item.DeviceID], item.ID)
		}
	}

	lanIPs, err := UnscopedFind[mysql.LANIP]()
	if err != nil {
		return err
	}
	for _, item := range lanIPs {
		td.idToVIFIP[item.ID] = item
		td.vifIDToVIFIPIDs[item.VInterfaceID] = append(td.vifIDToVIFIPIDs[item.VInterfaceID], item.ID)
	}

	wanIPs, err := UnscopedFind[mysql.WANIP]()
	if err != nil {
		return err
	}
	for _, item := range wanIPs {
		td.idToIPR[item.ID] = item
		td.vifIDToIPRIDs[item.VInterfaceID] = append(td.vifIDToIPRIDs[item.VInterfaceID], item.ID)
	}

	return nil
}
