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
	"fmt"

	ctrlcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

const IP_TYPE_WAN = 1

type WANIP struct {
	DataProvider
	dataTool *WANIPToolData
}

func NewWANIP() *WANIP {
	dp := &WANIP{newDataProvider(ctrlcommon.RESOURCE_TYPE_WAN_IP_EN), new(WANIPToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *WANIP) generate() (data []common.ResponseElem, err error) {
	err = p.dataTool.Init().Load()
	for _, item := range p.dataTool.WANIPs {
		data = append(data, p.generateOne(item))
	}
	return
}

func (p *WANIP) generateOne(item mysql.WANIP) common.ResponseElem {
	d := MySQLModelToMap(item)
	if _, ok := d["VINTERFACE_ID"]; ok {
		delete(d, "VINTERFACE_ID")
		d["VIFID"] = item.VInterfaceID
	}
	d["VL2_NET_ID"] = item.SubnetID
	d["IP_TYPE"] = IP_TYPE_WAN
	d["DOMAIN_NAME"] = p.dataTool.domainLcuuidToName[item.Domain]
	d["REGION_NAME"] = p.dataTool.regionLcuuidToName[item.Region]

	if item.VInterfaceID == 0 {
		return d
	}
	vif, ok := p.dataTool.vifIDToVIF[item.VInterfaceID]
	if !ok {
		return d
	}
	d["FIXED_IPS"] = p.dataTool.wanIPToRelatedLANIPs[item.IP]
	d["SUBNET_ID"] = vif.NetworkID
	var deviceName string
	var deviceVPCID int
	switch vif.DeviceType {
	case ctrlcommon.VIF_DEVICE_TYPE_VROUTER:
		device := p.dataTool.idToVGW[vif.DeviceID]
		deviceName, deviceVPCID = device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_VM:
		device := p.dataTool.idToVM[vif.DeviceID]
		deviceName, deviceVPCID = device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_HOST:
		device := p.dataTool.idToHost[vif.DeviceID]
		deviceName = device.Name
	case ctrlcommon.VIF_DEVICE_TYPE_DHCP_PORT:
		device := p.dataTool.idToDHCPPort[vif.DeviceID]
		deviceName, deviceVPCID = device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_POD:
		device := p.dataTool.idToPod[vif.DeviceID]
		deviceName, deviceVPCID = device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_POD_SERVICE:
		device := p.dataTool.idToPodService[vif.DeviceID]
		deviceName, deviceVPCID = device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_REDIS_INSTANCE:
		device := p.dataTool.idToRedisInstance[vif.DeviceID]
		deviceName, deviceVPCID = device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_RDS_INSTANCE:
		device := p.dataTool.idToRDSInstance[vif.DeviceID]
		deviceName, deviceVPCID = device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_POD_NODE:
		device := p.dataTool.idToPodNode[vif.DeviceID]
		deviceName, deviceVPCID = device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_LB:
		device := p.dataTool.idToLB[vif.DeviceID]
		deviceName, deviceVPCID = device.Name, device.VPCID
	case ctrlcommon.VIF_DEVICE_TYPE_NAT_GATEWAY:
		device := p.dataTool.idToNatGateWay[vif.DeviceID]
		deviceName, deviceVPCID = device.Name, device.VPCID
	default:
		return d
	}

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

	if vif.DeviceType == ctrlcommon.VIF_DEVICE_TYPE_VROUTER {
		fip, ok := p.dataTool.vl2IDToIPToFloatingIP[fmt.Sprintf("%d%s", vif.NetworkID, item.IP)]
		if !ok {
			return d
		}
		vm, ok := p.dataTool.idToVM[fip.VMID]
		if !ok {
			return d
		}
		d["DEVICE_TYPE"] = ctrlcommon.HOST_TYPE_VM
		d["DEVICE_NAME"] = vm.Name
		d["DEVICE_ID"] = vm.ID
	}

	return d
}

type WANIPToolData struct {
	WANIPs []mysql.WANIP

	wanIPToRelatedLANIPs map[string][]string

	BaseIPData

	vl2IDToIPToFloatingIP map[string]mysql.FloatingIP
}

func (td *WANIPToolData) Init() *WANIPToolData {
	td.regionLcuuidToName = make(map[string]string)
	td.domainLcuuidToName = make(map[string]string)

	td.vifIDToVIF = make(map[int]mysql.VInterface)
	td.wanIPToRelatedLANIPs = make(map[string][]string)
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
	td.vl2IDToIPToFloatingIP = make(map[string]mysql.FloatingIP)

	return td
}

func (td *WANIPToolData) Load() (err error) {
	td.WANIPs, err = UnscopedFind[mysql.WANIP]()
	if err != nil {
		return err
	}

	natRules, err := UnscopedSelect[mysql.NATRule]([]string{"floating_ip", "fixed_ip"})
	if err != nil {
		return err
	}
	for _, item := range natRules {
		td.wanIPToRelatedLANIPs[item.FloatingIP] = append(td.wanIPToRelatedLANIPs[item.FloatingIP], item.FixedIP)
	}

	fips, err := UnscopedFind[mysql.FloatingIP]()
	if err != nil {
		return err
	}
	for _, item := range fips {
		td.vl2IDToIPToFloatingIP[fmt.Sprintf("%d%s", item.NetworkID, item.IP)] = item
	}

	return td.BaseIPData.Load()
}

type BaseIPData struct {
	regionLcuuidToName map[string]string
	domainLcuuidToName map[string]string
	vifIDToVIF         map[int]mysql.VInterface
	idToVGW            map[int]mysql.VRouter
	idToVM             map[int]mysql.VM
	idToHost           map[int]mysql.Host
	idToDHCPPort       map[int]mysql.DHCPPort
	idToPod            map[int]mysql.Pod
	idToPodService     map[int]mysql.PodService
	idToRedisInstance  map[int]mysql.RedisInstance
	idToRDSInstance    map[int]mysql.RDSInstance
	idToPodNode        map[int]mysql.PodNode
	idToLB             map[int]mysql.LB
	idToNatGateWay     map[int]mysql.NATGateway
	vpcIDToName        map[int]string
	vl2IDToEPCID       map[int]int
}

func (b *BaseIPData) Load() (err error) {
	domains, err := UnscopedSelect[mysql.Domain]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range domains {
		b.domainLcuuidToName[item.Lcuuid] = item.Name
	}

	regions, err := UnscopedSelect[mysql.Region]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range regions {
		b.regionLcuuidToName[item.Lcuuid] = item.Name
	}

	vifs, err := UnscopedFind[mysql.VInterface]()
	if err != nil {
		return err
	}
	for _, vif := range vifs {
		b.vifIDToVIF[vif.ID] = vif
	}

	vgws, err := UnscopedFind[mysql.VRouter]()
	if err != nil {
		return err
	}
	for _, item := range vgws {
		b.idToVGW[item.ID] = item
	}

	vms, err := UnscopedFind[mysql.VM]()
	if err != nil {
		return err
	}
	for _, item := range vms {
		b.idToVM[item.ID] = item
	}

	hosts, err := UnscopedFind[mysql.Host]()
	if err != nil {
		return err
	}
	for _, item := range hosts {
		b.idToHost[item.ID] = item
	}

	dhcpPorts, err := UnscopedFind[mysql.DHCPPort]()
	if err != nil {
		return err
	}
	for _, item := range dhcpPorts {
		b.idToDHCPPort[item.ID] = item
	}

	pods, err := UnscopedFind[mysql.Pod]()
	if err != nil {
		return err
	}
	for _, item := range pods {
		b.idToPod[item.ID] = item
	}

	podServices, err := UnscopedFind[mysql.PodService]()
	if err != nil {
		return err
	}
	for _, item := range podServices {
		b.idToPodService[item.ID] = item
	}

	redisInstances, err := UnscopedFind[mysql.RedisInstance]()
	if err != nil {
		return err
	}
	for _, item := range redisInstances {
		b.idToRedisInstance[item.ID] = item
	}

	rdsInstance, err := UnscopedFind[mysql.RDSInstance]()
	if err != nil {
		return err
	}
	for _, item := range rdsInstance {
		b.idToRDSInstance[item.ID] = item
	}

	podNodes, err := UnscopedFind[mysql.PodNode]()
	if err != nil {
		return err
	}
	for _, item := range podNodes {
		b.idToPodNode[item.ID] = item
	}

	lbs, err := UnscopedFind[mysql.LB]()
	if err != nil {
		return err
	}
	for _, item := range lbs {
		b.idToLB[item.ID] = item
	}

	natGateways, err := UnscopedFind[mysql.NATGateway]()
	if err != nil {
		return err
	}
	for _, item := range natGateways {
		b.idToNatGateWay[item.ID] = item
	}

	epcs, err := UnscopedSelect[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range epcs {
		b.vpcIDToName[item.ID] = item.Name
	}

	vl2s, err := UnscopedSelect[mysql.Network]([]string{"id", "epc_id"})
	if err != nil {
		return err
	}
	for _, item := range vl2s {
		b.vl2IDToEPCID[item.ID] = item.VPCID
	}

	return nil
}
