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

const IP_TYPE_LAN = 3

type LANIP struct {
	DataProvider
	dataTool *LANIPToolData
}

func NewLANIP() *LANIP {
	dp := &LANIP{newDataProvider(ctrlcommon.RESOURCE_TYPE_LAN_IP_EN), new(LANIPToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *LANIP) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.LANIPs {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *LANIP) generateOne(item mysql.LANIP) common.ResponseElem {
	d := MySQLModelToMap(item)
	if _, ok := d["VINTERFACE_ID"]; ok {
		delete(d, "VINTERFACE_ID")
		d["VIFID"] = item.VInterfaceID
	}
	d["VL2_NET_ID"] = item.SubnetID
	d["IP_TYPE"] = IP_TYPE_LAN
	d["FIXED_IPS"] = p.dataTool.lanIPToRelatedWANIPs[item.IP]

	if item.VInterfaceID == 0 {
		return d
	}
	vif, ok := p.dataTool.vifIDToVIF[item.VInterfaceID]
	if !ok {
		return d
	}

	d["SUBNET_ID"] = vif.NetworkID
	var (
		deviceRegion string
		deviceDomain string
		deviceName   string
		deviceVPCID  int
	)
	switch vif.DeviceType {
	case ctrlcommon.VIF_DEVICE_TYPE_VROUTER:
		device := p.dataTool.idToVGW[vif.DeviceID]
		deviceRegion, deviceDomain, deviceName, deviceVPCID = device.Region, device.Domain, device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_VM:
		device := p.dataTool.idToVM[vif.DeviceID]
		deviceRegion, deviceDomain, deviceName, deviceVPCID = device.Region, device.Domain, device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_HOST:
		device := p.dataTool.idToHost[vif.DeviceID]
		deviceRegion, deviceDomain, deviceName = device.Region, device.Domain, device.Name
	case ctrlcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		device := p.dataTool.idToDHCPPort[vif.DeviceID]
		deviceRegion, deviceDomain, deviceName, deviceVPCID = device.Region, device.Domain, device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_POD:
		device := p.dataTool.idToPod[vif.DeviceID]
		deviceRegion, deviceDomain, deviceName, deviceVPCID = device.Region, device.Domain, device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		device := p.dataTool.idToPodService[vif.DeviceID]
		deviceRegion, deviceDomain, deviceName, deviceVPCID = device.Region, device.Domain, device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		device := p.dataTool.idToRedisInstance[vif.DeviceID]
		deviceRegion, deviceDomain, deviceName, deviceVPCID = device.Region, device.Domain, device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		device := p.dataTool.idToRDSInstance[vif.DeviceID]
		deviceRegion, deviceDomain, deviceName, deviceVPCID = device.Region, device.Domain, device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_POD_NODE:
		device := p.dataTool.idToPodNode[vif.DeviceID]
		deviceRegion, deviceDomain, deviceName, deviceVPCID = device.Region, device.Domain, device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_LB:
		device := p.dataTool.idToLB[vif.DeviceID]
		deviceRegion, deviceDomain, deviceName, deviceVPCID = device.Region, device.Domain, device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		device := p.dataTool.idToNatGateWay[vif.DeviceID]
		deviceRegion, deviceDomain, deviceName, deviceVPCID = device.Region, device.Domain, device.Name, device.VPCID
	default:
		return d
	}

	d["REGION"] = deviceRegion
	d["REGION_NAME"] = p.dataTool.regionLcuuidToName[deviceRegion]
	d["DOMAIN_NAME"] = p.dataTool.domainLcuuidToName[deviceDomain]

	d["DEVICE_NAME"] = deviceName
	if vif.DeviceType == ctrlcommon.VIF_DEVICE_TYPE_DHCP_PORT {
		d["DEVICE_NAME"] = d["IP"].(string)
	}
	d["DEVICE_TYPE"] = vif.DeviceType
	d["MAC_ADDRESS"] = vif.Mac
	d["DEVICE_ID"] = vif.DeviceID
	d["VIF_NAME"] = vif.Name

	if vif.DeviceType == ctrlcommon.VIF_DEVICE_TYPE_HOST {
		epcID := p.dataTool.vl2IDToEPCID[vif.NetworkID]
		d["EPC_ID"] = epcID
		d["EPC_NAME"] = p.dataTool.vpcIDToName[epcID]
	} else {
		d["EPC_ID"] = deviceVPCID
		d["EPC_NAME"] = p.dataTool.vpcIDToName[deviceVPCID]
	}

	return d
}

type LANIPToolData struct {
	LANIPs []mysql.LANIP

	lanIPToRelatedWANIPs map[string][]string

	BaseIPData
}

func (td *LANIPToolData) Init() *LANIPToolData {
	td.regionLcuuidToName = make(map[string]string)
	td.domainLcuuidToName = make(map[string]string)

	td.lanIPToRelatedWANIPs = make(map[string][]string)

	td.vifIDToVIF = make(map[int]mysql.VInterface)
	td.idToVGW = make(map[int]mysql.VRouter)
	td.idToVM = make(map[int]mysql.VM)
	td.idToHost = make(map[int]mysql.Host)
	td.idToDHCPPort = make(map[int]mysql.DHCPPort)
	td.idToPod = make(map[int]mysql.Pod)
	td.idToPodService = make(map[int]mysql.PodService)
	td.idToRedisInstance = make(map[int]mysql.RedisInstance)
	td.idToRDSInstance = make(map[int]mysql.RDSInstance)
	td.idToPodNode = make(map[int]mysql.PodNode)
	td.idToLB = make(map[int]mysql.LB)
	td.idToNatGateWay = make(map[int]mysql.NATGateway)

	td.vpcIDToName = make(map[int]string)
	td.vl2IDToEPCID = make(map[int]int)

	return td
}

func (td *LANIPToolData) Load() (err error) {
	td.LANIPs, err = UnscopedFind[mysql.LANIP]()
	if err != nil {
		return err
	}

	natRules, err := UnscopedSelect[mysql.NATRule]([]string{"floating_ip", "fixed_ip"})
	if err != nil {
		return err
	}
	for _, item := range natRules {
		td.lanIPToRelatedWANIPs[item.FixedIP] = append(td.lanIPToRelatedWANIPs[item.FixedIP], item.FloatingIP)
	}

	return td.BaseIPData.Load()
}
